//! Which arguments of a reader are places it opens, and whether each is one
//! the guard can name, for [`super::of`].
//!
//! A reader of a place known only when it runs may read a network device or a
//! share, so it is not reads-only. But only what the program opens as a file
//! is a place: a pattern, a count or an author (`grep "$P" .`, `head -n "$N"
//! x`) is not, and each reader's table entry says which arguments are
//! places.

use std::collections::HashMap;

use super::{git_subcommand, Effect};
use crate::path::{self, Place, Resolver};
use crate::powershell::Params;
use crate::unit::{plain, Arg, Binding, Unit};
use crate::Shell;

/// What judging a unit needs besides the unit.
pub(super) struct Context<'a> {
    pub(super) resolver: &'a Resolver,
    /// The first unit at each pipeline stage, for what a stage is handed.
    pub(super) producers: HashMap<(usize, usize), &'a Unit>,
}

/// Whether reading from `arg`, written from `dir`, is a read of a place the
/// guard can name and that is on this machine. Not when it is known only
/// when it runs, nor bash's `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT`, nor
/// on Windows a UNC path (`\\server\share`, `//server/share`,
/// `\\?\UNC\server\share`): reading those contacts the network, and a share
/// is offered the user's credentials.
pub(super) fn place_effect(
    resolver: &Resolver,
    shell: Shell,
    dir: Option<&Arg>,
    arg: &Arg,
) -> Effect {
    let Some(text) = arg.known() else {
        return Effect::Unknown;
    };
    let from = path::within(dir, arg, shell);
    if (shell == Shell::Posix && names_network_device(text))
        || resolver.network(dir, arg, shell)
        || matches!(resolver.place(&from, shell, false), Place::Unknown)
    {
        Effect::Unknown
    } else {
        Effect::ReadsOnly
    }
}

/// Whether `text` names one of bash's network devices.
pub(super) fn names_network_device(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("/dev/tcp/") || lower.contains("/dev/udp/")
}

/// A reader reads the places its path arguments name, so each must be one
/// the guard can name: a glob is a pattern over known folders and stays
/// known, a path known only when it runs (`cat $f`) does not. A name of the
/// network anywhere in the arguments is not reading. What a pipeline hands the
/// unit counts when the stages before it list known places.
pub(super) fn operands(unit: &Unit, key: &str, context: &Context<'_>) -> Effect {
    let mut effect = Effect::ReadsOnly;
    for arg in &unit.args {
        let network = (unit.shell == Shell::Posix && arg.known().is_some_and(names_network_device))
            || context.resolver.network(unit.dir.as_ref(), arg, unit.shell);
        if network {
            effect = Effect::Unknown;
        }
    }
    for arg in path_args(unit, key) {
        let own = match arg {
            Arg::Input if fed_by_listing(unit, context, false) => Effect::ReadsOnly,
            Arg::Input => Effect::Unknown,
            known => place_effect(context.resolver, unit.shell, unit.dir.as_ref(), known),
        };
        if own == Effect::Unknown {
            effect = Effect::Unknown;
        }
    }
    // A cmdlet that takes a path from the pipeline by value or by property
    // name reads whatever an earlier stage hands it, which is a path only
    // when that stage lists known places.
    if unit.shell == Shell::PowerShell && binds_pipeline(key) {
        let text = matches!(key, "select-string" | "sls");
        let handed = unit.stage.is_some_and(|stage| stage.index > 0);
        if handed && !fed_by_listing(unit, context, text) {
            effect = Effect::Unknown;
        }
    }
    effect
}

/// The PowerShell cmdlets whose path parameters take pipeline input.
fn binds_pipeline(key: &str) -> bool {
    matches!(
        key,
        "get-childitem"
            | "get-item"
            | "test-path"
            | "resolve-path"
            | "get-content"
            | "cat"
            | "gc"
            | "type"
            | "select-string"
            | "sls"
    )
}

/// Programs that print or test their arguments and open none of them.
pub(super) fn takes_no_paths(shell: Shell, key: &str) -> bool {
    match shell {
        Shell::Posix => matches!(
            key,
            "echo"
                | "printf"
                | "true"
                | "false"
                | "test"
                | "["
                | "basename"
                | "dirname"
                | "which"
                | "pwd"
        ),
        Shell::PowerShell => matches!(
            key,
            "write-output"
                | "write-host"
                | "echo"
                | "where-object"
                | "select-object"
                | "sort-object"
                | "measure-object"
                | "get-location"
                | "pwd"
        ),
        Shell::Cmd => matches!(key, "echo" | "cd" | "chdir"),
    }
}

// What a pipeline hands on.

/// Whether the unit's output is the names of what is in known places: `ls`,
/// `fd`, `dir`, `Get-ChildItem`, `git ls-files`, and a `find` that prints only
/// what it finds (`-printf` and `-exec` print any text).
fn lists(unit: &Unit) -> bool {
    let Some(key) = unit.key() else {
        return false;
    };
    match key.as_str() {
        "ls" | "fd" | "dir" | "get-childitem" => true,
        "find" => !unit.args.iter().filter_map(Arg::known).any(|text| {
            matches!(
                text,
                "-printf" | "-fprintf" | "-exec" | "-execdir" | "-ok" | "-okdir"
            )
        }),
        "git" => git_subcommand(&unit.args) == Some("ls-files"),
        _ => false,
    }
}

/// Whether the unit only selects, orders or shows part of what it is handed
/// (so what it hands on is still what the stage before it listed): it reads
/// no file of its own.
fn passes(unit: &Unit) -> bool {
    let Some(key) = unit.key() else {
        return false;
    };
    match unit.shell {
        Shell::Posix => {
            matches!(
                key.as_str(),
                "head" | "tail" | "sort" | "grep" | "egrep" | "fgrep"
            ) && path_args(unit, &key).is_empty()
        }
        Shell::PowerShell => match key.as_str() {
            "where-object" | "sort-object" => true,
            // `-Property` and a first argument can make up the objects.
            "select-object" => unit.args.iter().all(|arg| {
                arg.known().is_some_and(|text| {
                    let name = text.trim_start_matches('-').to_ascii_lowercase();
                    (text.starts_with('-')
                        && matches!(
                            name.as_str(),
                            "first" | "last" | "skip" | "skiplast" | "unique" | "index" | "wait"
                        ))
                        || text.chars().all(|c| c.is_ascii_digit())
                })
            }),
            _ => false,
        },
        Shell::Cmd => false,
    }
}

/// Whether what the stage before `unit` hands it is names from a listing,
/// through any stage that only passes them on. `text` says strings and
/// search results do as well, for a cmdlet that searches them rather than
/// opens them.
fn fed_by_listing(unit: &Unit, context: &Context<'_>, text: bool) -> bool {
    let mut at = unit.stage;
    while let Some(stage) = at.filter(|stage| stage.index > 0) {
        let Some(producer) = context
            .producers
            .get(&(stage.pipeline, stage.index - 1))
            .copied()
        else {
            return false;
        };
        if lists(producer) {
            return true;
        }
        if text
            && producer.key().is_some_and(|key| {
                matches!(
                    key.as_str(),
                    "get-content" | "cat" | "gc" | "type" | "select-string" | "sls"
                )
            })
        {
            return true;
        }
        if !passes(producer) {
            return false;
        }
        at = producer.stage;
    }
    false
}

// The path arguments of each reader.

/// How a program's arguments divide: which options take a value that is not
/// a place, which take a file, and whether the first operand is a pattern.
#[derive(Default)]
struct Spec {
    /// Short options whose value is not a place.
    valued: &'static str,
    valued_longs: &'static [&'static str],
    /// Short options whose value is a file the program reads.
    files: &'static str,
    file_longs: &'static [&'static str],
    /// Whether the first operand is a pattern.
    pattern: bool,
    /// The options that give the pattern or the places instead, so that no
    /// operand is the pattern.
    given: &'static str,
    given_longs: &'static [&'static str],
}

const LS: Spec = Spec {
    valued: "IwT",
    valued_longs: &[
        "hide",
        "ignore",
        "block-size",
        "color",
        "format",
        "indicator-style",
        "quoting-style",
        "sort",
        "time",
        "time-style",
        "tabsize",
        "width",
    ],
    ..none()
};
const HEAD: Spec = Spec {
    valued: "nc",
    valued_longs: &["lines", "bytes"],
    ..none()
};
const TAIL: Spec = Spec {
    valued: "ncs",
    valued_longs: &[
        "lines",
        "bytes",
        "pid",
        "sleep-interval",
        "max-unchanged-stats",
    ],
    ..none()
};
const STAT: Spec = Spec {
    valued: "c",
    valued_longs: &["format", "printf"],
    ..none()
};
const DU: Spec = Spec {
    valued: "dBtI",
    valued_longs: &[
        "max-depth",
        "block-size",
        "threshold",
        "exclude",
        "time",
        "time-style",
    ],
    files: "X",
    file_longs: &["exclude-from"],
    ..none()
};
const DF: Spec = Spec {
    valued: "Btx",
    valued_longs: &["block-size", "type", "exclude-type"],
    ..none()
};
const REALPATH: Spec = Spec {
    file_longs: &["relative-to", "relative-base"],
    ..none()
};
const DIFF: Spec = Spec {
    valued: "UCxILDWF",
    valued_longs: &[
        "unified",
        "context",
        "exclude",
        "ignore-matching-lines",
        "label",
        "ifdef",
        "width",
        "show-function-line",
    ],
    files: "SX",
    file_longs: &["starting-file", "exclude-from"],
    ..none()
};
const SORT: Spec = Spec {
    valued: "ktST",
    valued_longs: &[
        "key",
        "field-separator",
        "buffer-size",
        "temporary-directory",
        "parallel",
        "batch-size",
    ],
    file_longs: &["random-source", "files0-from"],
    ..none()
};
const FILE: Spec = Spec {
    valued: "eP",
    files: "fm",
    file_longs: &["files-from", "magic-file"],
    ..none()
};
const LESS: Spec = Spec {
    valued: "bhjpPtxyz#",
    files: "T",
    ..none()
};
const GREP: Spec = Spec {
    valued: "mABCdDe",
    valued_longs: &[
        "max-count",
        "after-context",
        "before-context",
        "context",
        "include",
        "exclude",
        "exclude-dir",
        "label",
        "color",
        "colour",
        "binary-files",
        "directories",
        "devices",
        "regexp",
        "group-separator",
    ],
    files: "f",
    file_longs: &["file", "exclude-from"],
    pattern: true,
    given: "ef",
    given_longs: &["regexp", "file"],
};
const RG: Spec = Spec {
    valued: "gtTmABCjEMrde",
    valued_longs: &[
        "glob",
        "iglob",
        "type",
        "type-not",
        "type-add",
        "type-clear",
        "max-count",
        "after-context",
        "before-context",
        "context",
        "threads",
        "encoding",
        "max-columns",
        "replace",
        "max-depth",
        "maxdepth",
        "sort",
        "sortr",
        "colors",
        "color",
        "context-separator",
        "field-context-separator",
        "field-match-separator",
        "max-filesize",
        "path-separator",
        "engine",
        "dfa-size-limit",
        "regex-size-limit",
        "regexp",
        "hyperlink-format",
        "pre-glob",
    ],
    files: "f",
    file_longs: &["file", "ignore-file"],
    pattern: true,
    given: "ef",
    given_longs: &["regexp", "file", "files", "type-list", "help", "version"],
};
const FD: Spec = Spec {
    valued: "eEtdSjco",
    valued_longs: &[
        "extension",
        "exclude",
        "type",
        "max-depth",
        "min-depth",
        "exact-depth",
        "size",
        "threads",
        "color",
        "owner",
        "changed-within",
        "changed-before",
        "max-results",
        "format",
        "hyperlink",
    ],
    file_longs: &["base-directory", "search-path", "ignore-file"],
    pattern: true,
    ..none()
};

/// A spec with nothing set, for `..none()` in the constants.
const fn none() -> Spec {
    Spec {
        valued: "",
        valued_longs: &[],
        files: "",
        file_longs: &[],
        pattern: false,
        given: "",
        given_longs: &[],
    }
}

/// The arguments of `unit` that are places its program opens.
fn path_args<'a>(unit: &'a Unit, key: &str) -> Vec<&'a Arg> {
    let args = unit.args.as_slice();
    if takes_no_paths(unit.shell, key) {
        return Vec::new();
    }
    match (unit.shell, key) {
        (Shell::Posix, "ls") => paths_of(args, &LS),
        (Shell::Posix, "cat" | "wc") => paths_of(args, &none()),
        (Shell::Posix, "head") => paths_of(args, &HEAD),
        (Shell::Posix, "tail") => paths_of(args, &TAIL),
        (Shell::Posix, "stat") => paths_of(args, &STAT),
        (Shell::Posix, "du") => paths_of(args, &DU),
        (Shell::Posix, "df") => paths_of(args, &DF),
        (Shell::Posix, "realpath") => paths_of(args, &REALPATH),
        (Shell::Posix, "diff") => paths_of(args, &DIFF),
        (Shell::Posix, "sort") => paths_of(args, &SORT),
        (Shell::Posix, "file") => paths_of(args, &FILE),
        (Shell::Posix, "less") => paths_of(args, &LESS),
        (Shell::Posix, "grep" | "egrep" | "fgrep") => paths_of(args, &GREP),
        (Shell::Posix, "rg") => paths_of(args, &RG),
        (Shell::Posix, "fd") => paths_of(args, &FD),
        (Shell::Posix, "find") => find_starts(args),
        (Shell::Posix, "git") => git_paths(args),
        (Shell::PowerShell, _) => powershell_paths(key, args),
        (Shell::Cmd, "findstr") => {
            // The first argument is what to search for, unless `/c:` or `/g:`
            // gives it.
            let operands = plain(args);
            let given = args.iter().filter_map(Arg::known).any(|text| {
                let lower = text.to_ascii_lowercase();
                lower.starts_with("/c:") || lower.starts_with("/g:")
            });
            operands.into_iter().skip(usize::from(!given)).collect()
        }
        (Shell::Cmd, _) => plain(args),
        // A reader this table has no entry for: every argument.
        _ => args.iter().collect(),
    }
}

/// The places a `find` searches: its arguments before the first test or
/// action, after its own options.
fn find_starts(args: &[Arg]) -> Vec<&Arg> {
    let mut at = 0;
    while let Some(text) = args.get(at).and_then(Arg::known) {
        match text {
            "-H" | "-L" | "-P" => at += 1,
            "-D" | "-O" => at += 2,
            text if text.starts_with("-O") && text.len() > 2 => at += 1,
            _ => break,
        }
    }
    args.get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|arg| {
            !arg.known()
                .is_some_and(|text| text.starts_with('-') || text == "(" || text == "!")
        })
        .collect()
}

/// The places a `git` command names: the folder of `-C`, what comes after
/// `--`, and every operand of `--no-index`. The other operands are revisions
/// and pathspecs inside the work tree, which git does not take outside it,
/// and are not read as places.
fn git_paths(args: &[Arg]) -> Vec<&Arg> {
    let mut paths = Vec::new();
    let no_index = args.iter().any(|arg| arg.known() == Some("--no-index"));
    let mut subcommand = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("-C") if !subcommand => paths.extend(iter.next()),
            Some("--") => {
                paths.extend(iter);
                break;
            }
            Some(text) if text.starts_with('-') => {}
            _ if !subcommand => subcommand = true,
            _ if no_index => paths.push(arg),
            _ => {}
        }
    }
    paths
}

/// The places a PowerShell cmdlet names: its `-Path` and `-LiteralPath`, and
/// its positional arguments (the first, for `Select-String`, is the pattern).
fn powershell_paths<'a>(key: &str, args: &'a [Arg]) -> Vec<&'a Arg> {
    let params = Params::read(args);
    let mut paths = params.values(&["path", "literalpath"]);
    let searching = matches!(key, "select-string" | "sls");
    let pattern = params.values(&["pattern"]);
    let skip = usize::from(searching && pattern.is_empty());
    paths.extend(params.positional.iter().skip(skip).copied());
    paths
}

/// One argument read for its flag: what is known of it up to the first
/// expansion, and whether anything after that is unknown.
fn shape(arg: &Arg) -> Option<(&str, bool)> {
    match arg {
        Arg::Known(text) => Some((text, false)),
        Arg::Template { text, .. } => {
            let at = text.find(crate::posix::OPAQUE).unwrap_or(text.len());
            Some((&text[..at], true))
        }
        Arg::Unknown(_) | Arg::Input => None,
    }
}

/// The arguments of a program that are places: its operands, and the values
/// of the options that take a file. What a valued option takes that is not
/// a place, or a pattern, is left out when it is known or its expansions
/// are quoted: an unquoted one could split into more arguments, options
/// among them, and counts as an operand.
fn paths_of<'a>(args: &'a [Arg], spec: &Spec) -> Vec<&'a Arg> {
    let mut paths = Vec::new();
    let mut operands: Vec<&Arg> = Vec::new();
    let mut given = false;
    let mut options = true;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let flag =
            shape(arg).filter(|(head, _)| options && head.starts_with('-') && head.len() > 1);
        let Some((head, tail)) = flag else {
            operands.push(arg);
            continue;
        };
        if head == "--" && !tail {
            options = false;
            continue;
        }
        if let Some(long) = head.strip_prefix("--") {
            let (name, equals) = long
                .split_once('=')
                .map_or((long, false), |(name, _)| (name, true));
            // `--name$x`: the name itself is not known.
            if tail && !equals {
                operands.push(arg);
                continue;
            }
            given |= spec.given_longs.contains(&name);
            if spec.file_longs.contains(&name) {
                if equals {
                    paths.extend(tail.then_some(arg));
                } else {
                    paths.extend(iter.next());
                }
            } else if equals {
                if tail && !inert(arg) {
                    paths.push(arg);
                }
            } else if spec.valued_longs.contains(&name) {
                paths.extend(iter.next().filter(|value| !inert(value)));
            }
            continue;
        }
        let bundle = &head[1..];
        for (at, letter) in bundle.char_indices() {
            let attached = at + letter.len_utf8() < bundle.len() || tail;
            given |= spec.given.contains(letter);
            if spec.files.contains(letter) {
                if attached {
                    paths.extend(tail.then_some(arg));
                } else {
                    paths.extend(iter.next());
                }
                break;
            }
            if spec.valued.contains(letter) {
                if attached {
                    if tail && !inert(arg) {
                        paths.push(arg);
                    }
                } else {
                    paths.extend(iter.next().filter(|value| !inert(value)));
                }
                break;
            }
        }
    }
    if spec.pattern && !given && !operands.is_empty() {
        let pattern = operands.remove(0);
        if !inert(pattern) {
            paths.push(pattern);
        }
    }
    paths.extend(operands);
    paths
}

/// Whether the value of `arg` is only data: known, or with every expansion
/// inside double quotes, where it stays one word.
pub(super) fn inert(arg: &Arg) -> bool {
    match arg {
        Arg::Known(_) => true,
        Arg::Template { source, .. } => expansions(source).iter().all(|found| found.quoted),
        Arg::Unknown(_) | Arg::Input => false,
    }
}

/// An expansion in the spelling of an argument.
struct Expansion {
    /// The variable, for `$name` and `${name}`; `None` for anything else
    /// (`$(…)`, `${x:-y}`, a backtick, `$1`).
    name: Option<String>,
    /// Whether it stands inside double quotes.
    quoted: bool,
}

/// The expansions in `source`, outside single quotes and not escaped.
fn expansions(source: &str) -> Vec<Expansion> {
    let chars: Vec<char> = source.chars().collect();
    let (mut single, mut double) = (false, false);
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        at += 1;
        if single {
            single = c != '\'';
            continue;
        }
        match c {
            '\\' => at += 1,
            '\'' if !double => single = true,
            '"' => double = !double,
            '`' => found.push(Expansion {
                name: None,
                quoted: double,
            }),
            '$' => {
                let word = |from: usize| -> String {
                    chars
                        .get(from..)
                        .unwrap_or_default()
                        .iter()
                        .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                        .collect()
                };
                let other = Expansion {
                    name: None,
                    quoted: double,
                };
                match chars.get(at).copied() {
                    Some('{') => {
                        let name = word(at + 1);
                        let length = name.chars().count();
                        if !name.is_empty() && chars.get(at + 1 + length) == Some(&'}') {
                            at += length + 2;
                            found.push(Expansion {
                                name: Some(name),
                                quoted: double,
                            });
                        } else {
                            found.push(other);
                        }
                    }
                    Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                        let name = word(at);
                        at += name.chars().count();
                        found.push(Expansion {
                            name: Some(name),
                            quoted: double,
                        });
                    }
                    Some('(' | '\'' | '"') => found.push(other),
                    Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(c) => {
                        at += 1;
                        found.push(other);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    found
}

// A `for` loop over words written out.

/// The units that a loop's body held, for each of the `bindings` around the
/// unit, with every combination of the words put in place of the variables:
/// a copy of the unit for each one, as if the body were written out. `None`
/// when nothing the unit has refers to a variable, or there are too many
/// combinations to read.
pub(super) fn substituted(unit: &Unit, enclosing: &[&Binding]) -> Option<Vec<Unit>> {
    /// The most combinations of words read for one unit.
    const LIMIT: usize = 64;
    if enclosing.is_empty() || enclosing.len() > 3 {
        return None;
    }
    let combinations = enclosing
        .iter()
        .try_fold(1_usize, |count, binding| {
            count.checked_mul(binding.words.len())
        })
        .filter(|count| *count <= LIMIT)?;
    let mut copies = Vec::with_capacity(combinations);
    let mut chosen = vec![0_usize; enclosing.len()];
    loop {
        let pairs: Vec<(&str, &str)> = enclosing
            .iter()
            .zip(&chosen)
            .filter_map(|(binding, &word)| {
                Some((binding.variable.as_str(), binding.words.get(word)?.as_str()))
            })
            .collect();
        let mut changed = false;
        let args: Vec<Arg> = unit
            .args
            .iter()
            .map(|arg| {
                substitute(arg, &pairs).map_or_else(
                    || arg.clone(),
                    |value| {
                        changed = true;
                        value
                    },
                )
            })
            .collect();
        if !changed {
            return None;
        }
        copies.push(Unit {
            args,
            ..unit.clone()
        });
        // The next combination, as an odometer.
        let mut place = 0;
        loop {
            let Some(digit) = chosen.get_mut(place) else {
                return Some(copies);
            };
            *digit += 1;
            if enclosing
                .get(place)
                .is_some_and(|binding| *digit < binding.words.len())
            {
                break;
            }
            *digit = 0;
            place += 1;
        }
    }
}

/// `arg` with the loop variables in `pairs` replaced by their words, when
/// every expansion in it is one of them and the rest is its text; `None`
/// when it holds none, or any other.
fn substitute(arg: &Arg, pairs: &[(&str, &str)]) -> Option<Arg> {
    let word = |name: &str| {
        pairs
            .iter()
            .find(|(variable, _)| *variable == name)
            .map(|(_, word)| *word)
    };
    match arg {
        Arg::Unknown(source) => {
            let found = expansions(source);
            let [only] = found.as_slice() else {
                return None;
            };
            let name = only.name.as_deref()?;
            let alone = *source == format!("${name}") || *source == format!("${{{name}}}");
            word(name)
                .filter(|_| alone)
                .map(|word| Arg::Known(word.to_string()))
        }
        Arg::Template { text, source } => {
            let found = expansions(source);
            let pieces: Vec<&str> = text.split(crate::posix::OPAQUE).collect();
            if found.is_empty() || pieces.len() != found.len() + 1 {
                return None;
            }
            let mut value = String::new();
            for (piece, expansion) in pieces.iter().zip(&found) {
                value.push_str(piece);
                value.push_str(word(expansion.name.as_deref()?)?);
            }
            value.push_str(pieces.last()?);
            Some(Arg::Known(value))
        }
        Arg::Known(_) | Arg::Input => None,
    }
}
