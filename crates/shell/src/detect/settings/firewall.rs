//! What the firewall programs load and add beyond a flush or a policy: a
//! ruleset loaded from a file or from the program's input, which replaces
//! the rules, and a rule that lets everything in.

use super::{getopt_operands, has_long, is_option, nft_commands, short_options, Given, NftWord};
use crate::detect::data::feeding;
use crate::detect::Checker;
use crate::launch::is_stdin;
use crate::unit::{Arg, Unit};

/// The reason of a load that replaces the rules.
pub(super) const REPLACES: &str = "replaces the firewall's rules";

/// The reason of a rule that opens the firewall.
pub(super) const OPENS: &str = "lets everything through the firewall";

/// A value given to an option.
enum Value<'a> {
    /// None was given.
    Missing,
    /// It is only known when the line runs.
    Unknown,
    /// Its text.
    Is(&'a str),
}

impl<'a> Value<'a> {
    fn of(arg: Option<&'a Arg>) -> Self {
        match arg {
            None => Self::Missing,
            Some(arg) => arg.known().map_or(Self::Unknown, Self::Is),
        }
    }

    /// Whether it is one of `names`, ignoring case, or only known when it
    /// runs.
    fn may_be(&self, names: &[&str]) -> bool {
        match self {
            Self::Missing => false,
            Self::Unknown => true,
            Self::Is(text) => names.iter().any(|name| name.eq_ignore_ascii_case(text)),
        }
    }
}

/// The addresses that match every source or destination.
const ANYWHERE: [&str; 6] = [
    "0.0.0.0/0",
    "0/0",
    "::/0",
    "0.0.0.0/0.0.0.0",
    "any",
    "anywhere",
];

/// Whether an address list (`a,b`) matches every address.
fn anywhere(text: &str) -> bool {
    text.split(',')
        .any(|part| ANYWHERE.iter().any(|any| any.eq_ignore_ascii_case(part)))
}

/// Whether a protocol, by name or number, reaches every service: all of
/// them, TCP or UDP (`icmp` and the like do not).
fn every_service(protocol: &str) -> bool {
    ["all", "0", "tcp", "6", "udp", "17", "any"]
        .iter()
        .any(|name| name.eq_ignore_ascii_case(protocol))
}

/// What an `iptables` rule is, read from its options.
#[derive(Default)]
struct Added<'a> {
    /// The chain it is added to (`-A`, `-I`, `-R`); `Some(Unknown)` when
    /// only known when it runs.
    chain: Option<Value<'a>>,
    /// Its target (`-j`); a `-g` goes to a chain, which is not a verdict.
    target: Option<Value<'a>>,
    /// Whether anything narrows what it matches.
    narrowed: bool,
}

impl<'a> Added<'a> {
    /// Read one option, `name` a long name or a letter, given `value` (the
    /// rest of a bundle, an `=value`, or the next argument, taken only when
    /// used). Returns whether the value was used.
    fn option(&mut self, name: &Opt<'_>, value: Value<'a>) -> bool {
        let is = |full: &str, least: usize, letter: Option<char>| match name {
            Opt::Long(long) => is_option(long, full, least),
            Opt::Short(short) => Some(*short) == letter,
        };
        if is("append", 2, Some('A')) || is("insert", 3, Some('I')) || is("replace", 3, Some('R')) {
            self.chain = Some(value);
        } else if is("jump", 1, Some('j')) {
            self.target = Some(value);
        } else if is("goto", 2, Some('g')) {
            self.target = Some(Value::Is("goto"));
        } else if is("source", 2, Some('s')) || is("destination", 3, Some('d')) {
            self.narrowed |= !matches!(value, Value::Is(text) if anywhere(text));
        } else if is("protocol", 2, Some('p')) {
            self.narrowed |= !matches!(value, Value::Is(text) if every_service(text));
        } else if is("match", 2, Some('m')) {
            // A comment matches every packet.
            self.narrowed |=
                !matches!(value, Value::Is(text) if text.eq_ignore_ascii_case("comment"));
        } else if is("table", 2, Some('t'))
            || is("wait-interval", 6, Some('W'))
            || is("modprobe", 2, Some('M'))
            || is("comment", 3, None)
        {
            return true;
        } else if is("verbose", 1, Some('v'))
            || is("numeric", 2, Some('n'))
            || is("exact", 1, Some('x'))
            || is("line-numbers", 1, None)
            || is("ipv4", 4, Some('4'))
            || is("ipv6", 4, Some('6'))
            || is("wait", 4, Some('w'))
        {
            return false;
        } else {
            // A match (`-i lo`, `--dport 22`), and anything not read.
            self.narrowed = true;
            return matches!(name, Opt::Short('i' | 'o'));
        }
        true
    }

    /// Whether the rule lets every packet into the machine or through it.
    fn opens(&self) -> bool {
        let into = self
            .chain
            .as_ref()
            .is_some_and(|chain| chain.may_be(&["INPUT", "FORWARD"]));
        let accepts = self
            .target
            .as_ref()
            .is_some_and(|target| target.may_be(&["ACCEPT"]));
        into && accepts && !self.narrowed
    }
}

/// An option as written: a long name, or one letter of a bundle.
enum Opt<'a> {
    Long(&'a str),
    Short(char),
}

/// Whether `args`, given to `iptables` (or `ebtables`, `arptables`), add a
/// rule that ACCEPTs everything on the input or forward chain: with no
/// match, or only matches of everything (`-s 0.0.0.0/0`, a comment) or of
/// every service (`-p all`, `-p tcp`). A match only known when it runs is
/// taken to narrow it, as a rule's other values are.
pub(super) fn opens_everything(args: &[Arg]) -> bool {
    let mut rule = Added::default();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            // A word only known when it runs may be a match.
            rule.narrowed = true;
            continue;
        };
        if text == "--" {
            break;
        }
        if text == "!" {
            rule.narrowed = true;
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            let value = match attached {
                Some(value) => Value::Is(value),
                None => Value::of(iter.peek().copied()),
            };
            if rule.option(&Opt::Long(name), value) && attached.is_none() {
                iter.next();
            }
            continue;
        }
        let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty()) else {
            // A rule number, or an operand not read.
            continue;
        };
        for (at, letter) in bundle.char_indices() {
            let rest = &bundle[at + letter.len_utf8()..];
            let value = if rest.is_empty() {
                Value::of(iter.peek().copied())
            } else {
                Value::Is(rest)
            };
            let used = rule.option(&Opt::Short(letter), value);
            if used {
                if rest.is_empty() {
                    iter.next();
                }
                break;
            }
        }
    }
    rule.opens()
}

/// The values `args` give the long option `full` (or a prefix of it of at
/// least `least` letters), `--name=value` or `--name value`, up to `--`.
fn long_values<'a>(args: &'a [Arg], full: &str, least: usize) -> Vec<Value<'a>> {
    let mut found = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        // `--name=$value` names the option, with a value only known when
        // it runs.
        let (text, holes) = match arg {
            Arg::Known(text) => (text.as_str(), false),
            Arg::Template { text, .. } => (text.as_str(), true),
            Arg::Unknown(_) | Arg::Input | Arg::Null => continue,
        };
        if text == "--" {
            break;
        }
        let Some(long) = text.strip_prefix("--") else {
            continue;
        };
        let (name, attached) = long
            .split_once('=')
            .map_or((long, None), |(name, value)| (name, Some(value)));
        if name.contains(['$', '`']) || holes && attached.is_none() {
            continue;
        }
        if is_option(name, full, least) {
            found.push(match attached {
                None => Value::of(iter.next()),
                Some(_) if holes => Value::Unknown,
                Some(value) => Value::Is(value),
            });
        }
    }
    found
}

/// The iptables arguments of `firewall-cmd --direct`: what `--passthrough
/// FAMILY ARGS` (and `--add-passthrough`) hands iptables, and the rule
/// `--add-rule FAMILY TABLE CHAIN PRIORITY ARGS` inserts, as `-t TABLE -I
/// CHAIN ARGS`. `None` when it has neither.
pub(super) fn direct_rule(args: &[Arg]) -> Option<Vec<Arg>> {
    for (at, arg) in args.iter().enumerate() {
        let Some(long) = arg.known().and_then(|text| text.strip_prefix("--")) else {
            continue;
        };
        let (name, attached) = long
            .split_once('=')
            .map_or((long, None), |(name, value)| (name, Some(value)));
        // The family is the value, or the next argument.
        let after = if attached.is_some() { at + 1 } else { at + 2 };
        let rest = args.get(after..).unwrap_or_default();
        if is_option(name, "passthrough", 4) || is_option(name, "add-passthrough", 7) {
            return Some(rest.to_vec());
        }
        if is_option(name, "add-rule", 6) {
            let (Some(table), Some(chain)) = (rest.first(), rest.get(1)) else {
                return Some(Vec::new());
            };
            let mut rule = vec![
                Arg::Known("-t".to_string()),
                table.clone(),
                Arg::Known("-I".to_string()),
                chain.clone(),
            ];
            rule.extend(rest.iter().skip(3).cloned());
            return Some(rule);
        }
    }
    None
}

/// Whether `firewall-cmd` lets everything in through a zone: a target of
/// ACCEPT (`--set-target=ACCEPT`), or a source of anywhere added to the
/// trusted zone. A value only known when it runs may be either.
pub(super) fn zone_opens(args: &[Arg]) -> bool {
    let accepts = long_values(args, "set-target", 5)
        .iter()
        .any(|target| target.may_be(&["ACCEPT"]));
    let everyone = long_values(args, "add-source", 10)
        .iter()
        .any(|source| match source {
            Value::Missing => false,
            Value::Unknown => true,
            Value::Is(text) => anywhere(text),
        });
    let trusted = long_values(args, "zone", 2)
        .iter()
        .any(|zone| zone.may_be(&["trusted"]));
    accepts || everyone && trusted
}

/// Whether an `nft` command line sets a chain's policy to accept (or to a
/// policy only known when it runs) on a hook that lets things in: the last
/// hook named before it, unless that is `output` or `postrouting`.
pub(super) fn nft_opens(commands: &[Vec<NftWord>]) -> bool {
    let words: Vec<Option<&str>> = commands
        .iter()
        .flatten()
        .map(|word| word.as_deref().map(|word| word.trim_matches(['{', '}'])))
        .filter(|word| *word != Some(""))
        .collect();
    let mut hook: Option<Option<&str>> = None;
    for (at, word) in words.iter().enumerate() {
        let next = words.get(at + 1).copied();
        match word {
            Some("hook") => hook = next,
            Some("policy") => {
                let accepts = match next {
                    None => false,
                    Some(None) => true,
                    Some(Some(policy)) => policy == "accept",
                };
                let leaves = matches!(hook, Some(Some("output" | "postrouting")));
                if accepts && !leaves {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether `ufw` operands (`allow from any`) let everything in: an `allow`
/// (also after `insert N`, `prepend` or `route`) from anywhere to anywhere,
/// in, over every protocol or TCP or UDP, with nothing else to narrow it (a
/// port, an interface, an application). A source or protocol only known
/// when it runs may be any.
pub(super) fn ufw_opens(words: &[&Arg]) -> bool {
    let lower = |arg: &&Arg| arg.known().map(str::to_ascii_lowercase);
    let mut words = words.iter().map(lower).peekable();
    loop {
        match words.next().flatten().as_deref() {
            Some("insert") => {
                words.next();
            }
            Some("prepend" | "route") => {}
            Some("allow") => break,
            _ => return false,
        }
    }
    let mut extended = false;
    while let Some(word) = words.next() {
        match word.as_deref() {
            Some("in" | "log" | "log-all") => {}
            Some("comment") => {
                words.next();
            }
            Some("proto") => match words.next() {
                Some(Some(protocol)) if every_service(&protocol) => {}
                Some(None) => {}
                _ => return false,
            },
            Some("from" | "to") => {
                extended = true;
                match words.next() {
                    Some(Some(address)) if anywhere(&address) => {}
                    Some(None) => {}
                    _ => return false,
                }
            }
            _ => return false,
        }
    }
    extended
}

/// Whether a ruleset `nft` loads adds nothing: every command lists, and a
/// `#` that starts a word comments out the rest of its line (on a line with
/// no quote, where it may be inside a string).
fn nft_lists_only(text: &str) -> bool {
    let mut stripped = String::new();
    for line in text.lines() {
        let line = match line.find('#') {
            Some(at)
                if !line.contains(['"', '\''])
                    && line[..at].chars().last().is_none_or(char::is_whitespace) =>
            {
                &line[..at]
            }
            _ => line,
        };
        stripped.push_str(line);
        stripped.push('\n');
    }
    nft_commands(&[&Arg::Known(stripped)])
        .iter()
        .all(|command| match command.first() {
            None => true,
            Some(verb) => verb.as_deref() == Some("list"),
        })
}

/// Whether a ruleset `iptables-restore` loads adds nothing: blank and
/// comment lines only (a table named, even empty, is flushed).
fn restore_adds_nothing(text: &str) -> bool {
    text.lines().all(|line| {
        let line = line.trim();
        line.is_empty() || line.starts_with('#')
    })
}

/// Whether a `cat` reads its input and nothing else: none of its arguments
/// is a file but `-` and the input's own names.
fn reads_only_input(unit: &Unit) -> bool {
    unit.args.iter().all(|arg| {
        arg.known()
            .is_some_and(|text| is_stdin(text) || text.starts_with('-'))
    })
}

/// What a load reads.
#[derive(Clone, Copy, PartialEq)]
enum Source {
    /// Nothing is loaded.
    Nothing,
    /// The program's input.
    Input,
    /// A file, which is not read (or a file only known when it runs).
    File,
}

impl Source {
    /// The source of a load from `file`, after loads from `self`: a file
    /// outweighs the input.
    fn and(self, file: &Value<'_>) -> Self {
        let source = match file {
            Value::Missing => return self,
            Value::Is(name) if is_stdin(name) => Self::Input,
            Value::Is(_) | Value::Unknown => Self::File,
        };
        if self == Self::File {
            self
        } else {
            source
        }
    }
}

impl Checker<'_> {
    /// The text the unit at `at` reads from its input, when the line shows
    /// all of it: a here-string or here-document of plain text, or what the
    /// `echo` and `printf` of the stage before it say. `None` when any of it
    /// is a file, is only known when it runs, or nothing on the line feeds
    /// it.
    fn input_texts(&mut self, at: usize, unit: &Unit) -> Option<Vec<String>> {
        if matches!(unit.stdin, Some(ref arg) if arg.known().is_none()) {
            return None;
        }
        if self
            .split
            .redirects
            .iter()
            .any(|redirect| redirect.input && redirect.units.contains(&at))
        {
            return None;
        }
        let mut texts = Vec::new();
        for text in self.split.fed_to(at) {
            texts.push(text.known()?.to_string());
        }
        if let Some(key) = feeding(unit) {
            let producers = self.stages.get(&key).cloned().unwrap_or_default();
            for producer in producers {
                let unit = self.split.units.get(producer)?;
                let says = match unit.key().as_deref() {
                    Some("echo" | "printf" | "write-output") => true,
                    // A `cat` passes on only the plain text fed to it.
                    Some("cat") => {
                        reads_only_input(unit)
                            && matches!(unit.stdin, Some(Arg::Known(_)))
                            && !self.split.redirects.iter().any(|redirect| {
                                redirect.input && redirect.units.contains(&producer)
                            })
                    }
                    _ => false,
                };
                if !says {
                    return None;
                }
            }
            for text in self.stage_said(key).iter() {
                texts.push(text.known()?.to_string());
            }
        }
        (!texts.is_empty()).then_some(texts)
    }

    /// Whether what the unit at `at` loads from `source` may add rules:
    /// `adds_nothing` reads text that is on the line.
    fn loads(
        &mut self,
        at: usize,
        unit: &Unit,
        source: Source,
        adds_nothing: fn(&str) -> bool,
    ) -> bool {
        match source {
            Source::Nothing => false,
            Source::File => true,
            Source::Input => self
                .input_texts(at, unit)
                .is_none_or(|texts| !texts.iter().all(|text| adds_nothing(text))),
        }
    }

    /// `nft -f FILE` and `nft -i` load a ruleset, from a file or the input;
    /// `-c` only checks it.
    pub(super) fn nft_loads(&mut self, at: usize, unit: &Unit) -> bool {
        let args = unit.args.as_slice();
        let shorts = short_options(args, "fIDd");
        if shorts.iter().any(|(letter, _)| *letter == 'c') || has_long(args, "check", 2) {
            return false;
        }
        let mut source = Source::Nothing;
        for (letter, given) in &shorts {
            source = match (letter, given) {
                ('f', Given::Attached(file)) => source.and(&Value::Is(file)),
                ('f', Given::Next(file)) => source.and(&Value::of(Some(file))),
                ('i', _) => source.and(&Value::Is("-")),
                _ => source,
            };
        }
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            let Some(text) = arg.known() else { continue };
            if text == "--" {
                break;
            }
            let Some(long) = text.strip_prefix("--") else {
                continue;
            };
            let (name, attached) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            if is_option(name, "file", 2) {
                let file = attached.map_or_else(|| Value::of(iter.next()), Value::Is);
                source = source.and(&file);
            } else if is_option(name, "interactive", 3) {
                source = source.and(&Value::Is("-"));
            }
        }
        self.loads(at, unit, source, nft_lists_only)
    }

    /// `iptables-restore` (and its kin) loads the ruleset in a file operand,
    /// or else its input; `-t` only tests it.
    pub(super) fn restore_loads(&mut self, at: usize, unit: &Unit) -> bool {
        let args = unit.args.as_slice();
        let tests = short_options(args, "TWM")
            .iter()
            .any(|(letter, _)| *letter == 't')
            || has_long(args, "test", 2);
        if tests {
            return false;
        }
        let files = getopt_operands(args, "TWM", &["table", "wait-interval", "modprobe"]);
        let source = if files.iter().all(|file| file.known().is_some_and(is_stdin)) {
            Source::Input
        } else {
            Source::File
        };
        self.loads(at, unit, source, restore_adds_nothing)
    }
}
