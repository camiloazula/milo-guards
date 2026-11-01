//! Whether a line only reads, and where: the second answer beside
//! `classify`, taken from the same split and the same findings.
//!
//! A line is [`Effect::ReadsOnly`] only when everything in it is understood
//! and none of it changes anything: every unit is a known reader run with
//! reading flags, no redirect writes a file, nothing is known only when it
//! runs, and the rules found nothing but an elevation or a read of a key. A
//! reader is a program in a short table; a program the table does not know
//! is [`Effect::Unknown`], never reading. The same table says which files a
//! reader opens, which is what the rule about reading a key judges. Where the
//! reads land is [`Reach`]: the `reach` module says what a unit reads.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};

use crate::path::{self, Place, Resolver};

mod git;
pub(crate) mod operands;
mod paths;
mod reach;
use crate::unit::{has_flag, moves_to, Arg, Split, Unit};
use crate::{Finding, Rule, Shell};
use operands::{dashed, inert, operands, place_effect, substituted, unquoted, Context};
use reach::Manner;

pub use paths::{How, ReadPath};

/// What a line does to the machine, as far as the guard can read: the answer
/// of [`effect`](fn@crate::effect), beside [`classify`](crate::classify)'s.
///
/// The two answers are independent. `mkdir build` is safe and
/// [`Changes`](Self::Changes); `cat ~/.ssh/id_ed25519` is
/// [`ReadsOnly`](Self::ReadsOnly) with a [`Reach::Beyond`], and not a line to
/// run without a thought. What to do with either is the caller's policy.
///
/// This enum is exhaustive on purpose, as [`Rule`] is: the three answers
/// are the whole question, and a fourth would change what a caller's gate
/// means by "reads only", so it must break every caller's `match` at
/// compile time rather than reach a fallback arm nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Every part of the line is a known reader run with reading flags and
    /// nothing is written: it changes nothing on the machine. The [`Reach`]
    /// says whether what it reads stays in the workspace.
    ReadsOnly(Reach),
    /// Something in the line is a known writer, or writes through a
    /// redirect, or is a package manager or a build tool, or a rule found
    /// it risky for what it changes.
    Changes,
    /// The guard cannot say: a program it does not know, a program or script
    /// known only when it runs, a line it could not read in full. Never
    /// [`ReadsOnly`](Self::ReadsOnly): what cannot be read is not reads-only.
    Unknown,
}

/// Where the reads of a line that only reads land: the second half of
/// [`Effect::ReadsOnly`].
///
/// `Reach` is about reading what is not the project's. [`Workspace`](Self::Workspace)
/// says every place the line reads is the project's own: inside a workspace
/// folder (the repository's history, a startup file and a path the caller
/// protects are inside it too), a temporary file, or the null device.
/// [`Beyond`](Self::Beyond) says at least one read lands elsewhere: the home
/// folder, a system folder, anything else outside the workspace, or a secret (a
/// key, a credential) even inside it. A line that reads nothing (`echo hi`,
/// `pwd`) is `Workspace`.
///
/// What a line reads is every file operand and the source of every `<`
/// redirect, the folders a lister lists, and the working directory when a
/// reader with no file operand reads it implicitly (`ls`, `git status`,
/// `rg TODO`, `find`, `grep -r x`): so `ls` run from outside the workspace,
/// or after `cd ~`, is `Beyond`. A reader whose implicit input the guard
/// cannot place is `Beyond`, never `Workspace`. A reader that goes below the
/// folders it names (a recursive search, a listing of every name) reaches what
/// is below them: a folder that holds a secret read that way is `Beyond`.
///
/// This enum is exhaustive on purpose, for the same reason as [`Effect`]: a
/// third answer would change what a caller's careful mode means by "stays in
/// the workspace".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reach {
    /// Every read lands inside a workspace folder, in a temporary file, or on
    /// the null device, and none is a secret.
    Workspace,
    /// At least one read lands elsewhere, or is a secret.
    Beyond,
}

/// What one unit or one line does, before [`Reach`] is added to a line that
/// only reads: the answer the tables give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Reads,
    Changes,
    Unknown,
}

/// The effect of a line already split and judged by the rules. `classify`
/// uses the same `split` and `findings`, so the two answers cannot disagree
/// about what the units are.
pub(crate) fn of(split: &Split, findings: &[Finding], resolver: &Resolver) -> Effect {
    read(split, findings, resolver, false).effect
}

/// The places a line that only reads reads, and how each is read, from the
/// same reading as [`of`]: `None` for any other line. Absolute, sorted,
/// without repeats. A read that is not a place on a disk (a device, a path on
/// another drive's own working directory) has none and is left out; it is
/// judged by its place already.
pub(crate) fn paths(
    split: &Split,
    findings: &[Finding],
    resolver: &Resolver,
) -> Option<Vec<ReadPath>> {
    let reads = read(split, findings, resolver, true);
    matches!(reads.effect, Effect::ReadsOnly(_))
        .then(|| paths::resolve(&reads.landed, &reads.followed, resolver))
}

/// What reading a line gave: its effect, and when the paths were asked for,
/// where each read landed and which pipeline stages hand names on to a
/// program that opens them.
struct Read {
    effect: Effect,
    landed: Vec<paths::Landed>,
    followed: BTreeSet<(usize, usize)>,
}

/// Read the line once: its effect, and the paths when `collect` asks.
fn read(split: &Split, findings: &[Finding], resolver: &Resolver, collect: bool) -> Read {
    let mut seen = Seen::default();
    for finding in findings {
        seen.add(rule_effect(finding.rule));
    }
    // What is read but not a unit.
    seen.unknown |= split.kept.opaque;
    seen.changes |= split.kept.changes;
    seen.unknown |= split.kept.sets.iter().any(|name| !harmless(name));
    seen.unknown |= split.kept.loops.iter().any(|name| !plain_loop(name));
    for write in &split.writes {
        let target = path::within(write.dir.as_ref(), &write.target, write.shell);
        let place = resolver.place(&target, write.shell, write.hidden);
        seen.changes |= !matches!(place, Place::Null);
    }
    // The first unit at each pipeline stage, for what a stage is handed.
    let mut producers = HashMap::new();
    for unit in &split.units {
        if let Some(stage) = unit.stage {
            producers
                .entry((stage.pipeline, stage.index))
                .or_insert(unit);
        }
    }
    let context = Context {
        resolver,
        producers,
        beyond: Cell::new(false),
        landed: collect.then(|| RefCell::new(Vec::new())),
        followed: RefCell::default(),
        stage: Cell::new(None),
    };
    for read in &split.reads {
        seen.add(place_effect(
            &context,
            read.shell,
            read.dir.as_ref(),
            &read.target,
            Manner::default(),
        ));
    }
    for (at, unit) in split.units.iter().enumerate() {
        context.stage.set(unit.stage);
        // A `for` loop over words written out is read with each word in place
        // of its variable, as if the body were written out.
        let enclosing: Vec<_> = split
            .bindings
            .iter()
            .filter(|binding| binding.units.contains(&at))
            .collect();
        match substituted(unit, &enclosing) {
            Some(copies) => {
                for copy in &copies {
                    seen.add(unit_effect(copy, &context));
                }
            }
            None => seen.add(unit_effect(unit, &context)),
        }
    }
    let effect = seen.effect(context.beyond.get());
    Read {
        effect,
        landed: context.landed.map(RefCell::into_inner).unwrap_or_default(),
        followed: context.followed.into_inner(),
    }
}

/// What has been seen so far: a change beats not knowing, which beats
/// reading.
#[derive(Default)]
struct Seen {
    changes: bool,
    unknown: bool,
}

impl Seen {
    fn add(&mut self, effect: Kind) {
        match effect {
            Kind::Reads => {}
            Kind::Changes => self.changes = true,
            Kind::Unknown => self.unknown = true,
        }
    }

    /// A line with a known writer changes things whatever else it holds;
    /// what the guard cannot read only matters when nothing is known to
    /// change. A line that only reads reaches `beyond` the workspace or
    /// stays in it.
    fn effect(&self, beyond: bool) -> Effect {
        if self.changes {
            Effect::Changes
        } else if self.unknown {
            Effect::Unknown
        } else if beyond {
            Effect::ReadsOnly(Reach::Beyond)
        } else {
            Effect::ReadsOnly(Reach::Workspace)
        }
    }
}

/// What a finding of `rule` says about the line's effect. No fallback arm: a
/// new rule must be placed here.
fn rule_effect(rule: Rule) -> Kind {
    match rule {
        Rule::Delete
        | Rule::WipeDisk
        | Rule::Overwrite
        | Rule::GitDiscard
        | Rule::GitRemote
        | Rule::GitHistory
        | Rule::Permissions
        | Rule::SystemSettings
        | Rule::StopSystem => Kind::Changes,
        Rule::RunDownloaded | Rule::RunInput | Rule::Unknown | Rule::Unreadable => Kind::Unknown,
        // Running as root changes nothing by itself: `sudo cat` reads only.
        // Nor does reading a key: `cat ~/.ssh/id_ed25519` reads only, and the
        // finding says which file (the line's `Reach` is `Beyond`); what to
        // do about it is the caller's.
        Rule::Elevated | Rule::ReadSecret => Kind::Reads,
        // Sending a secret away sends data off the machine: it is not a read.
        Rule::SendSecret => Kind::Changes,
    }
}

/// Variables that set a language or a display and nothing that runs: the
/// only ones a line may set and still be read. Any other can change which
/// program runs (`PATH`, `LD_PRELOAD`) or what it does (`GIT_PAGER`,
/// `LESSOPEN`).
const HARMLESS_VARIABLES: [&str; 12] = [
    "LANG",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_TIME",
    "TZ",
    "TERM",
    "COLUMNS",
    "LINES",
    "NO_COLOR",
    "CLICOLOR",
];

/// Whether setting the variable `name` (as written; PowerShell's `env:X`
/// too) leaves what programs run and do alone.
fn harmless(name: &str) -> bool {
    let name = name
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("env:"))
        .map_or(name, |_| &name[4..]);
    HARMLESS_VARIABLES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// The names zsh ties to the environment, which a `for` variable of that
/// name would change.
const TIED: [&str; 4] = ["path", "cdpath", "fpath", "manpath"];

/// Whether a `for` loop's variable is only a name for each of its words: a
/// lower-case name that is not one zsh ties to a search path.
fn plain_loop(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && !TIED.contains(&name)
}

/// The wrappers that only run the program after them, so what they run
/// decides. `find` is the one a `-exec` makes. Any other wrapper (`flock`
/// makes its lock file, `nohup` may make `nohup.out`, `tmux` and `screen`
/// start sessions) is a step the guard does not judge.
const WRAPPERS: [&str; 15] = [
    "sudo", "doas", "gsudo", "pkexec", "env", "nice", "ionice", "time", "timeout", "gtimeout",
    "stdbuf", "xargs", "command", "builtin", "find",
];

/// The folders a program may be named in and still be the one the shell
/// finds by its name: `/usr/bin/cat` is `cat`, `./cat` and `/tmp/x/cat` are
/// whatever someone put there.
const SYSTEM_FOLDERS: [&str; 4] = ["/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"];

/// What one unit does.
fn unit_effect(unit: &Unit, context: &Context<'_>) -> Kind {
    judge_unit(&received(unit), context)
}

/// The unit with its arguments as the program receives them: a PowerShell
/// word with quotes in it (`--contents="\\evil\s"`) reaches the program with
/// the quotes taken off, and is judged so.
pub(crate) fn received(unit: &Unit) -> Cow<'_, Unit> {
    if unit.shell == Shell::PowerShell
        && unit
            .args
            .iter()
            .any(|arg| arg.known().is_some_and(|text| text.contains(['"', '\''])))
    {
        let mut copy = unit.clone();
        for arg in &mut copy.args {
            if let Arg::Known(text) = arg {
                *text = unquoted(text);
            }
        }
        return Cow::Owned(copy);
    }
    Cow::Borrowed(unit)
}

/// What one unit does, its arguments as the program receives them.
fn judge_unit(unit: &Unit, context: &Context<'_>) -> Kind {
    let resolver = context.resolver;
    let Some(key) = program(unit) else {
        return Kind::Unknown;
    };
    // A `cd` the guard follows only moves the line.
    let own = if let Some(target) = moves_to(unit) {
        // Going into a folder is a read of it: `cd ~` leaves the workspace
        // for whatever follows, a line of its own or the caller's next one.
        let at = path::within(unit.dir.as_ref(), &target, unit.shell);
        let place = resolver.place(&at, unit.shell, unit.hidden);
        context.land(unit.shell, None, &at, place, Manner::default());
        if matches!(place, Place::Unknown) {
            Kind::Unknown
        } else {
            Kind::Reads
        }
    } else {
        match unit.shell {
            Shell::Posix => posix(&key, unit),
            Shell::PowerShell => powershell(&key, unit),
            Shell::Cmd => cmd(&key, unit),
        }
    };
    let known_wrappers = unit
        .wrappers
        .iter()
        .all(|wrapper| WRAPPERS.contains(&wrapper.as_str()));
    match own {
        Kind::Reads if !known_wrappers => Kind::Unknown,
        Kind::Reads => operands(unit, &key, context),
        other => other,
    }
}

/// The name the tables know the unit's program by, when the program is
/// the one that name means: known, not a script or batch file, and not
/// named in a folder other than the system's.
fn program(unit: &Unit) -> Option<String> {
    let text = unit.program.known()?;
    let base = match text.rfind(['/', '\\']) {
        Some(at) => {
            let folder = &text[..at];
            if unit.shell != Shell::Posix || !SYSTEM_FOLDERS.contains(&folder) {
                return None;
            }
            &text[at + 1..]
        }
        None => text,
    };
    let lower = base.to_ascii_lowercase();
    // `ls.bat` and `cat.exe` (in a POSIX shell) are files, not `ls` and
    // `cat`; on Windows `dir.exe` is `dir`.
    let scripts: &[&str] = if unit.shell == Shell::Posix {
        &[".exe", ".com", ".bat", ".cmd"]
    } else {
        &[".com", ".bat", ".cmd"]
    };
    if scripts.iter().any(|suffix| lower.ends_with(suffix)) {
        return None;
    }
    unit.key()
}

/// What the options of a wrapper do, `own` being the arguments before the
/// program it runs. A wrapper is let through by [`WRAPPERS`] only when
/// every option it is given is one of these: an option the guard does not
/// know could do anything (`sudo -e` edits a file, `env -P` changes where
/// programs are found), and `time -o FILE` writes one.
pub(crate) fn wrapper(key: &str, own: &[Arg]) -> Kind {
    let none = Options::default();
    let spec = match key {
        "sudo" | "doas" | "gsudo" | "pkexec" => Options {
            flags: "nHSk",
            valued: "ug",
            longs: &["non-interactive", "set-home", "stdin", "reset-timestamp"],
            valued_longs: &["user", "group"],
            ..none
        },
        // Assignments are bare words, and are recorded as variables set.
        // `-C` and `--chdir` move the program to another folder, which the
        // guard does not follow: they are not read, so the line is `Unknown`.
        "env" => Options {
            flags: "i0",
            valued: "u",
            longs: &["ignore-environment", "null"],
            valued_longs: &["unset"],
            ..none
        },
        "nice" => Options {
            flags: "0123456789",
            valued: "n",
            valued_longs: &["adjustment"],
            ..none
        },
        "ionice" => Options {
            flags: "t",
            valued: "cn",
            longs: &["ignore"],
            valued_longs: &["class", "classdata"],
            ..none
        },
        // GNU and BSD `time` write their report to a file with `-o`.
        "time" => Options {
            flags: "pvla",
            valued: "f",
            writes: "o",
            longs: &["portability", "verbose", "append"],
            valued_longs: &["format"],
            write_longs: &["output"],
        },
        "timeout" | "gtimeout" => Options {
            flags: "v",
            valued: "sk",
            longs: &["preserve-status", "foreground", "verbose"],
            valued_longs: &["signal", "kill-after"],
            ..none
        },
        "stdbuf" => Options {
            valued: "ioe",
            valued_longs: &["input", "output", "error"],
            ..none
        },
        "xargs" => Options {
            flags: "0rtxpo",
            valued: "nPLsdEeRSIJil",
            longs: &[
                "null",
                "no-run-if-empty",
                "verbose",
                "exit",
                "open-tty",
                "interactive",
                "show-limits",
            ],
            valued_longs: &[
                "max-args",
                "max-procs",
                "max-lines",
                "max-chars",
                "delimiter",
                "eof",
                "replace",
                "process-slot-var",
            ],
            ..none
        },
        "command" => Options { flags: "p", ..none },
        _ => return Kind::Reads,
    };
    options(own, &spec)
}

/// The options of a wrapper: short letters that stand alone, that take a
/// value, and that write; long names the same. A value follows an option
/// as the rest of its bundle (`-n5`), after `=`, or as the next argument.
#[derive(Default)]
struct Options {
    flags: &'static str,
    valued: &'static str,
    writes: &'static str,
    longs: &'static [&'static str],
    valued_longs: &'static [&'static str],
    write_longs: &'static [&'static str],
}

/// `Changes` when a writing option is given, `Unknown` when one the spec
/// does not name is, or one known only when it runs.
fn options(own: &[Arg], spec: &Options) -> Kind {
    let (mut changes, mut unknown) = (false, false);
    let mut iter = own.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            unknown = true;
            continue;
        };
        if text == "--" {
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, false), |(name, _)| (name, true));
            if spec.write_longs.contains(&name) {
                changes = true;
                if !value {
                    unknown |= iter.next().is_some_and(dashed);
                }
            } else if spec.valued_longs.contains(&name) {
                if !value {
                    unknown |= iter.next().is_some_and(dashed);
                }
            } else if !spec.longs.contains(&name) {
                unknown = true;
            }
        } else if let Some(bundle) = text.strip_prefix('-') {
            for (at, letter) in bundle.char_indices() {
                let value = at + letter.len_utf8() < bundle.len();
                if spec.writes.contains(letter) {
                    changes = true;
                } else if !spec.valued.contains(letter) && !spec.flags.contains(letter) {
                    unknown = true;
                    break;
                }
                if spec.writes.contains(letter) || spec.valued.contains(letter) {
                    if !value {
                        unknown |= iter.next().is_some_and(dashed);
                    }
                    break;
                }
            }
        }
    }
    if changes {
        Kind::Changes
    } else if unknown {
        Kind::Unknown
    } else {
        Kind::Reads
    }
}

/// The long options of a program that takes any unambiguous prefix of one
/// (GNU `sort`, `file` and `less` do): one counts as reading only when it is
/// exactly one of `reads`; a prefix of a writing option is a write, and
/// anything else is not known, a prefix of a program-running one included.
/// Names compare without case, as `less` does.
fn abbreviated(args: &[Arg], reads: &[&str], writes: &[&str]) -> Kind {
    let (mut changes, mut unknown) = (false, false);
    for text in args.iter().filter_map(Arg::known) {
        if text == "--" {
            break;
        }
        let Some(long) = text.strip_prefix("--") else {
            continue;
        };
        let name = long.split('=').next().unwrap_or_default();
        let lower = name.to_ascii_lowercase();
        let prefix_of = |full: &&str| !lower.is_empty() && full.starts_with(&lower);
        if reads.contains(&name) {
        } else if writes.iter().any(prefix_of) {
            changes = true;
        } else {
            // Any other option, a program-running one (`--compress-program`)
            // by prefix included, is not one the guard has named.
            unknown = true;
        }
    }
    if changes {
        Kind::Changes
    } else if unknown {
        Kind::Unknown
    } else {
        Kind::Reads
    }
}

/// Both the long options by prefix and the short ones for a program.
fn gnu(args: &[Arg], shorts: &[char], reads: &[&str], writes: &[&str]) -> Kind {
    let short = shorts
        .iter()
        .any(|&letter| has_flag(args, Some(letter), None));
    let long = abbreviated(args, reads, writes);
    if short || long == Kind::Changes {
        Kind::Changes
    } else if long == Kind::Unknown {
        Kind::Unknown
    } else {
        Kind::Reads
    }
}

/// Programs that change the machine whatever their flags: the files, the
/// processes, the system.
const WRITERS: [&str; 24] = [
    "rm", "rmdir", "unlink", "shred", "mkdir", "touch", "mv", "cp", "ln", "install", "chmod",
    "chown", "chgrp", "tee", "dd", "truncate", "mkfifo", "mktemp", "patch", "kill", "pkill",
    "killall", "shutdown", "reboot",
];

/// Package managers and build tools: they write whatever subcommand they
/// are given.
const TOOLS: [&str; 33] = [
    "cargo", "rustc", "rustup", "npm", "npx", "yarn", "pnpm", "bun", "pip", "pip3", "pipx", "uv",
    "poetry", "gem", "bundle", "go", "make", "cmake", "ninja", "gradle", "mvn", "brew", "apt",
    "apt-get", "dpkg", "dnf", "yum", "pacman", "winget", "choco", "scoop", "msbuild", "dotnet",
];

/// A flag as [`has_flag`] takes it: a short letter, a long name, or both.
type Flag = (Option<char>, Option<&'static str>);

fn given(args: &[Arg], flags: &[Flag]) -> bool {
    flags
        .iter()
        .any(|&(short, long)| has_flag(args, short, long))
}

/// A reader some of whose flags write or run something. An argument known
/// only when it runs is judged with the places the program opens (see
/// [`operands`]), where it is not a value or a pattern.
fn guarded(args: &[Arg], writes: &[Flag], runs: &[Flag]) -> Kind {
    if given(args, writes) {
        Kind::Changes
    } else if given(args, runs) {
        Kind::Unknown
    } else {
        Kind::Reads
    }
}

/// The table for a POSIX shell.
fn posix(key: &str, unit: &Unit) -> Kind {
    let args = unit.args.as_slice();
    match key {
        // No flag of these writes or runs anything.
        "ls" | "cat" | "head" | "tail" | "wc" | "stat" | "pwd" | "echo" | "grep" | "egrep"
        | "fgrep" | "diff" | "du" | "df" | "which" | "realpath" | "basename" | "dirname"
        | "true" | "false" | "test" | "[" => Kind::Reads,
        // `printf -v NAME` sets a variable.
        "printf" => match args.first().map(Arg::known) {
            Some(Some(first)) if first.starts_with("-v") => Kind::Unknown,
            Some(None) => Kind::Unknown,
            _ => Kind::Reads,
        },
        // GNU `sort`, `file` and `less` take any unambiguous prefix of a
        // long option, so only the long options named here read (see
        // [`abbreviated`]). `sort -o`/`--output` writes and
        // `--compress-program` runs a program.
        "sort" => gnu(
            args,
            &['o'],
            &[
                "reverse",
                "unique",
                "numeric-sort",
                "general-numeric-sort",
                "human-numeric-sort",
                "version-sort",
                "month-sort",
                "ignore-case",
                "ignore-leading-blanks",
                "dictionary-order",
                "stable",
                "check",
                "key",
                "field-separator",
            ],
            &["output"],
        ),
        // `file -C` compiles a magic file.
        "file" => gnu(
            args,
            &['C'],
            &[
                "brief",
                "mime",
                "mime-type",
                "mime-encoding",
                "dereference",
                "no-dereference",
                "keep-going",
            ],
            &["compile"],
        ),
        // `-o` and `-O` log what is read to a file, an argument that starts
        // with `+` is a command (`+!rm x`), and `-k` reads a lesskey file.
        "less" => {
            let command = args
                .iter()
                .any(|arg| arg.known().is_some_and(|text| text.starts_with('+')));
            // `-k` names a lesskey file, whose `#env` section can set
            // `LESSOPEN`.
            let command = command || has_flag(args, Some('k'), None);
            match gnu(
                args,
                &['o', 'O'],
                &[
                    "quit-if-one-screen",
                    "RAW-CONTROL-CHARS",
                    "chop-long-lines",
                    "LINE-NUMBERS",
                    "line-numbers",
                    "ignore-case",
                    "IGNORE-CASE",
                    "no-init",
                    "quit-at-eof",
                    "hilite-search",
                ],
                &["log-file"],
            ) {
                Kind::Reads if command => Kind::Unknown,
                other => other,
            }
        }
        // `--pre` and `--hostname-bin` run a program; `-z` runs a
        // decompressor.
        "rg" => guarded(
            args,
            &[],
            &[
                (Some('z'), Some("search-zip")),
                (None, Some("pre")),
                (None, Some("hostname-bin")),
            ],
        ),
        // A prefix of `--exec` or `--exec-batch` is read as one too, in case
        // the program takes abbreviations.
        "fd" => {
            let abbreviated = args.iter().filter_map(Arg::known).any(|text| {
                let name = text
                    .strip_prefix("--")
                    .and_then(|long| long.split('=').next())
                    .unwrap_or_default();
                !name.is_empty() && ("exec".starts_with(name) || "exec-batch".starts_with(name))
            });
            if abbreviated {
                Kind::Unknown
            } else {
                guarded(
                    args,
                    &[],
                    &[(Some('x'), Some("exec")), (Some('X'), Some("exec-batch"))],
                )
            }
        }
        "find" => find(args),
        "git" => git(args),
        key if WRITERS.contains(&key) || TOOLS.contains(&key) => Kind::Changes,
        _ => Kind::Unknown,
    }
}

/// `find`: the actions that write; what `-exec` and `-ok` run are units of
/// their own. An argument known only when it runs could be `-delete`, unless
/// it is the value of a test that takes one (`-name "$p"`) and is quoted.
fn find(args: &[Arg]) -> Kind {
    const WRITES: [&str; 5] = ["-delete", "-fprint", "-fprint0", "-fprintf", "-fls"];
    /// The tests whose next argument is a pattern, a number or a type.
    const VALUED: [&str; 28] = [
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-wholename",
        "-iwholename",
        "-lname",
        "-ilname",
        "-regex",
        "-iregex",
        "-type",
        "-xtype",
        "-newer",
        "-mtime",
        "-mmin",
        "-atime",
        "-amin",
        "-ctime",
        "-cmin",
        "-size",
        "-perm",
        "-user",
        "-group",
        "-maxdepth",
        "-mindepth",
        "-links",
        "-samefile",
        "-regextype",
    ];
    if args
        .iter()
        .filter_map(Arg::known)
        .any(|text| WRITES.contains(&text))
    {
        return Kind::Changes;
    }
    // The start points are read from a file, which the guard never sees.
    if args.iter().any(|arg| arg.known() == Some("-files0-from")) {
        return Kind::Unknown;
    }
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some(text) if VALUED.contains(&text) => {
                if iter
                    .next()
                    .is_some_and(|value| dashed(value) || !inert(value))
                {
                    return Kind::Unknown;
                }
            }
            Some(_) => {}
            None => return Kind::Unknown,
        }
    }
    Kind::Reads
}

/// The subcommands of git that change the repository or the work tree.
const GIT_WRITERS: [&str; 22] = [
    "add",
    "commit",
    "push",
    "pull",
    "fetch",
    "merge",
    "rebase",
    "reset",
    "checkout",
    "switch",
    "restore",
    "clean",
    "stash",
    "rm",
    "mv",
    "init",
    "clone",
    "cherry-pick",
    "revert",
    "apply",
    "am",
    "gc",
];

/// The subcommand of a `git` command, after the options that only choose
/// where to look and how to page.
pub(super) fn git_subcommand(args: &[Arg]) -> Option<&str> {
    let mut at = 0;
    loop {
        match args.get(at)?.known()? {
            "-C" => at += 2,
            "--no-pager" | "-P" | "--no-optional-locks" => at += 1,
            other if other.starts_with('-') => return None,
            other => return Some(other),
        }
    }
}

/// `git`: after the options that only choose where to look and how to page,
/// the subcommand. `-c` and every other option before it can make git run a
/// command, so they are not read.
fn git(args: &[Arg]) -> Kind {
    let mut at = 0;
    let subcommand = loop {
        let Some(text) = args.get(at).and_then(Arg::known) else {
            return Kind::Unknown;
        };
        match text {
            "-C" => at += 2,
            "--no-pager" | "-P" | "--no-optional-locks" => at += 1,
            other if other.starts_with('-') => return Kind::Unknown,
            other => break other,
        }
    };
    let rest = args.get(at + 1..).unwrap_or_default();
    match subcommand {
        // Each knows the options that read; any other is `Unknown`, and
        // `--output` writes a file (see [`git`]).
        "status" | "log" | "diff" | "show" | "blame" | "rev-parse" | "ls-files" => {
            git::read(subcommand, rest).map_or(Kind::Unknown, |reading| reading.effect)
        }
        "branch" => listing(rest, &BRANCH),
        "tag" => listing(rest, &TAG),
        "remote" => match rest {
            [] => Kind::Reads,
            [only] if matches!(only.known(), Some("-v" | "--verbose")) => Kind::Reads,
            [first, ..]
                if matches!(
                    first.known(),
                    Some(
                        "add"
                            | "remove"
                            | "rm"
                            | "rename"
                            | "set-url"
                            | "set-head"
                            | "set-branches"
                            | "prune"
                            | "update"
                    )
                ) =>
            {
                Kind::Changes
            }
            _ => Kind::Unknown,
        },
        other if GIT_WRITERS.contains(&other) => Kind::Changes,
        _ => Kind::Unknown,
    }
}

/// The flags of a git subcommand that lists and can also write: what only
/// lists, what takes a value, what writes. An operand names the thing to
/// create unless the subcommand is listing (`--list` takes patterns).
struct Listing {
    flags: &'static [&'static str],
    valued: &'static [&'static str],
    writes: &'static [&'static str],
    /// Letters allowed in a bundle of short flags (`-avv`), digits too.
    letters: &'static str,
    /// Letters that write.
    writing: &'static str,
}

const BRANCH: Listing = Listing {
    flags: &[
        "--all",
        "--remotes",
        "--verbose",
        "--show-current",
        "--list",
        "--color",
        "--no-color",
        "--column",
        "--no-column",
        "--ignore-case",
        "--abbrev",
        "--no-abbrev",
        "--omit-empty",
    ],
    valued: &[
        "--contains",
        "--no-contains",
        "--merged",
        "--no-merged",
        "--points-at",
        "--sort",
        "--format",
    ],
    writes: &[
        "--delete",
        "--move",
        "--copy",
        "--force",
        "--set-upstream-to",
        "--unset-upstream",
        "--track",
        "--no-track",
        "--edit-description",
        "--create-reflog",
    ],
    letters: "arvi",
    writing: "dDmMcCfut",
};

const TAG: Listing = Listing {
    flags: &[
        "--list",
        "--color",
        "--no-color",
        "--column",
        "--no-column",
        "--ignore-case",
    ],
    valued: &[
        "--contains",
        "--no-contains",
        "--merged",
        "--no-merged",
        "--points-at",
        "--sort",
        "--format",
    ],
    writes: &[
        "--delete",
        "--annotate",
        "--sign",
        "--local-user",
        "--force",
        "--message",
        "--file",
        "--cleanup",
        "--create-reflog",
    ],
    letters: "lni",
    writing: "dasufmF",
};

/// `git branch` and `git tag`: reading only when every flag is one that
/// lists and there is no operand to create (`git branch topic` makes one),
/// except patterns after `--list`.
fn listing(args: &[Arg], spec: &Listing) -> Kind {
    let (mut changes, mut unknown, mut operand, mut list) = (false, false, false, false);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            unknown = true;
            continue;
        };
        if text == "--" {
            operand |= iter.next().is_some();
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, false), |(name, _)| (name, true));
            let name = format!("--{name}");
            if spec.writes.contains(&name.as_str()) {
                changes = true;
            } else if spec.valued.contains(&name.as_str()) {
                if !value {
                    unknown |= iter.next().is_some_and(dashed);
                }
            } else if spec.flags.contains(&name.as_str()) {
                list |= name == "--list";
            } else {
                unknown = true;
            }
        } else if let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty()) {
            for letter in bundle.chars() {
                // `-l` lists, with patterns, where it is a letter at all.
                list |= letter == 'l' && spec.letters.contains('l');
                if spec.writing.contains(letter) {
                    changes = true;
                } else if !spec.letters.contains(letter) && !letter.is_ascii_digit() {
                    unknown = true;
                }
            }
        } else {
            operand = true;
        }
    }
    if changes || (operand && !list && !unknown) {
        Kind::Changes
    } else if unknown {
        Kind::Unknown
    } else {
        Kind::Reads
    }
}

/// The table for PowerShell, by the cmdlet's name (an alias the guard knows
/// is already its cmdlet).
fn powershell(key: &str, unit: &Unit) -> Kind {
    match key {
        "get-childitem" | "get-content" | "select-string" | "get-item" | "get-location"
        | "test-path" | "resolve-path" | "write-output" | "write-host" | "where-object"
        | "select-object" | "sort-object" | "measure-object" | "cat" | "gc" | "type" | "sls"
        | "echo" | "pwd" => Kind::Reads,
        "remove-item"
        | "copy-item"
        | "move-item"
        | "set-content"
        | "add-content"
        | "out-file"
        | "tee-object"
        | "new-item"
        | "rename-item"
        | "clear-content"
        | "set-itemproperty"
        | "new-itemproperty"
        | "remove-itemproperty"
        | "set-acl"
        | "stop-process"
        | "mkdir"
        | "md"
        | "ren" => Kind::Changes,
        "git" => git(&unit.args),
        key if TOOLS.contains(&key) => Kind::Changes,
        _ => Kind::Unknown,
    }
}

/// The table for cmd.
fn cmd(key: &str, unit: &Unit) -> Kind {
    match key {
        "dir" | "type" | "findstr" | "echo" | "cd" | "chdir" => Kind::Reads,
        "del" | "erase" | "rd" | "rmdir" | "md" | "mkdir" | "copy" | "xcopy" | "move" | "ren"
        | "rename" | "robocopy" | "attrib" | "icacls" | "takeown" | "format" | "diskpart"
        | "reg" | "taskkill" | "shutdown" => Kind::Changes,
        "git" => git(&unit.args),
        key if TOOLS.contains(&key) => Kind::Changes,
        _ => Kind::Unknown,
    }
}
