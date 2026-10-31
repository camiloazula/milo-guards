//! Whether a line only reads: the second answer beside `classify`, taken from
//! the same split and the same findings.
//!
//! A line is [`Effect::ReadsOnly`] only when everything in it is understood
//! and none of it changes anything: every unit is a known reader run with
//! reading flags, no redirect writes a file, nothing is known only when it
//! runs, and the rules found nothing but an elevation. A reader is a program
//! in a short table; a program the table does not know is
//! [`Effect::Unknown`], never reading.

use crate::path::{self, Place, Resolver};
use crate::unit::{has_flag, moves_to, Arg, Split, Unit};
use crate::{Finding, Rule, Shell};

/// What a line does to the machine, as far as the guard can read: the answer
/// of [`effect`](fn@crate::effect), beside [`classify`](crate::classify)'s.
///
/// The two answers are independent. `mkdir build` is safe and
/// [`Changes`](Self::Changes); `cat ~/.ssh/id_ed25519` is
/// [`ReadsOnly`](Self::ReadsOnly) and not a line to run without a thought.
/// What to do with either is the caller's policy.
///
/// This enum is exhaustive on purpose, as [`Rule`] is: the three answers
/// are the whole question, and a fourth would change what a caller's gate
/// means by "reads only", so it must break every caller's `match` at
/// compile time rather than reach a fallback arm nobody chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Effect {
    /// Every part of the line is a known reader run with reading flags and
    /// nothing is written: it changes nothing on the machine (it may still
    /// read what it should not).
    ReadsOnly,
    /// Something in the line is a known writer, or writes through a
    /// redirect, or is a package manager or a build tool, or a rule found
    /// it risky for what it changes.
    Changes,
    /// The guard cannot say: a program it does not know, a program or script
    /// known only when it runs, a line it could not read in full. Never
    /// [`ReadsOnly`](Self::ReadsOnly): what cannot be read is not reads-only.
    Unknown,
}

/// The effect of a line already split and judged by the rules. `classify`
/// uses the same `split` and `findings`, so the two answers cannot disagree
/// about what the units are.
pub(crate) fn of(split: &Split, findings: &[Finding], resolver: &Resolver) -> Effect {
    let mut seen = Seen::default();
    for finding in findings {
        seen.add(rule_effect(finding.rule));
    }
    // What is read but not a unit.
    seen.unknown |= split.opaque;
    seen.unknown |= split.sets.iter().any(|name| !harmless(name));
    seen.unknown |= split.loops.iter().any(|name| !plain_loop(name));
    for write in &split.writes {
        let target = path::within(write.dir.as_ref(), &write.target, write.shell);
        let place = resolver.place(&target, write.shell, write.hidden);
        seen.changes |= !matches!(place, Place::Null);
    }
    for unit in &split.units {
        seen.add(unit_effect(unit, resolver));
    }
    seen.effect()
}

/// What has been seen so far: a change beats not knowing, which beats
/// reading.
#[derive(Default)]
struct Seen {
    changes: bool,
    unknown: bool,
}

impl Seen {
    fn add(&mut self, effect: Effect) {
        match effect {
            Effect::ReadsOnly => {}
            Effect::Changes => self.changes = true,
            Effect::Unknown => self.unknown = true,
        }
    }

    /// A line with a known writer changes things whatever else it holds;
    /// what the guard cannot read only matters when nothing is known to
    /// change.
    fn effect(&self) -> Effect {
        if self.changes {
            Effect::Changes
        } else if self.unknown {
            Effect::Unknown
        } else {
            Effect::ReadsOnly
        }
    }
}

/// What a finding of `rule` says about the line's effect. No fallback arm: a
/// new rule must be placed here.
fn rule_effect(rule: Rule) -> Effect {
    match rule {
        Rule::Delete
        | Rule::WipeDisk
        | Rule::Overwrite
        | Rule::GitDiscard
        | Rule::GitRemote
        | Rule::GitHistory
        | Rule::Permissions
        | Rule::SystemSettings
        | Rule::StopSystem => Effect::Changes,
        Rule::RunDownloaded | Rule::RunInput | Rule::Unknown | Rule::Unreadable => Effect::Unknown,
        // Running as root changes nothing by itself: `sudo cat` reads only.
        Rule::Elevated => Effect::ReadsOnly,
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
fn unit_effect(unit: &Unit, resolver: &Resolver) -> Effect {
    let Some(key) = program(unit) else {
        return Effect::Unknown;
    };
    // A `cd` the guard follows only moves the line.
    let own = if let Some(target) = moves_to(unit) {
        let at = path::within(unit.dir.as_ref(), &target, unit.shell);
        if matches!(resolver.place(&at, unit.shell, false), Place::Unknown) {
            Effect::Unknown
        } else {
            Effect::ReadsOnly
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
        Effect::ReadsOnly if !known_wrappers => Effect::Unknown,
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
/// only when it runs could be one of them.
fn guarded(args: &[Arg], writes: &[Flag], runs: &[Flag]) -> Effect {
    if given(args, writes) {
        Effect::Changes
    } else if given(args, runs) || args.iter().any(|arg| arg.known().is_none()) {
        Effect::Unknown
    } else {
        Effect::ReadsOnly
    }
}

/// The table for a POSIX shell.
fn posix(key: &str, unit: &Unit) -> Effect {
    let args = unit.args.as_slice();
    match key {
        // No flag of these writes or runs anything.
        "ls" | "cat" | "head" | "tail" | "wc" | "stat" | "pwd" | "echo" | "grep" | "egrep"
        | "fgrep" | "diff" | "du" | "df" | "which" | "realpath" | "basename" | "dirname"
        | "true" | "false" | "test" | "[" => Effect::ReadsOnly,
        // `printf -v NAME` sets a variable.
        "printf" => match args.first().map(Arg::known) {
            Some(Some(first)) if first.starts_with("-v") => Effect::Unknown,
            Some(None) => Effect::Unknown,
            _ => Effect::ReadsOnly,
        },
        "sort" => guarded(
            args,
            &[(Some('o'), Some("output"))],
            &[(None, Some("compress-program"))],
        ),
        // `file -C` compiles a magic file.
        "file" => guarded(args, &[(Some('C'), Some("compile"))], &[]),
        // `-o` and `-O` log what is read to a file, and an argument that
        // starts with `+` is a command (`+!rm x`).
        "less" => {
            let command = args
                .iter()
                .any(|arg| arg.known().is_some_and(|text| text.starts_with('+')));
            match guarded(
                args,
                &[(Some('o'), Some("log-file")), (Some('O'), Some("LOG-FILE"))],
                &[],
            ) {
                Effect::ReadsOnly if command => Effect::Unknown,
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
        "fd" => guarded(
            args,
            &[],
            &[(Some('x'), Some("exec")), (Some('X'), Some("exec-batch"))],
        ),
        "find" => find(args),
        "git" => git(args),
        key if WRITERS.contains(&key) || TOOLS.contains(&key) => Effect::Changes,
        _ => Effect::Unknown,
    }
}

/// `find`: the actions that write; what `-exec` and `-ok` run are units of
/// their own. An argument known only when it runs could be `-delete`.
fn find(args: &[Arg]) -> Effect {
    const WRITES: [&str; 5] = ["-delete", "-fprint", "-fprint0", "-fprintf", "-fls"];
    if args
        .iter()
        .filter_map(Arg::known)
        .any(|text| WRITES.contains(&text))
    {
        Effect::Changes
    } else if args.iter().any(|arg| arg.known().is_none()) {
        Effect::Unknown
    } else {
        Effect::ReadsOnly
    }
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

/// `git`: after the options that only choose where to look and how to page,
/// the subcommand. `-c` and every other option before it can make git run a
/// command, so they are not read.
fn git(args: &[Arg]) -> Effect {
    let mut at = 0;
    let subcommand = loop {
        let Some(text) = args.get(at).and_then(Arg::known) else {
            return Effect::Unknown;
        };
        match text {
            "-C" => at += 2,
            "--no-pager" | "-P" | "--no-optional-locks" => at += 1,
            other if other.starts_with('-') => return Effect::Unknown,
            other => break other,
        }
    };
    let rest = args.get(at + 1..).unwrap_or_default();
    match subcommand {
        // `--output` writes the diff to a file, `--ext-diff` runs the
        // configured program, `--help` starts a viewer.
        "status" | "log" | "diff" | "show" | "blame" | "rev-parse" | "ls-files" => guarded(
            rest,
            &[(None, Some("output"))],
            &[(None, Some("ext-diff")), (None, Some("help"))],
        ),
        "branch" => listing(rest, &BRANCH),
        "tag" => listing(rest, &TAG),
        "remote" => match rest {
            [] => Effect::ReadsOnly,
            [only] if matches!(only.known(), Some("-v" | "--verbose")) => Effect::ReadsOnly,
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
                Effect::Changes
            }
            _ => Effect::Unknown,
        },
        other if GIT_WRITERS.contains(&other) => Effect::Changes,
        _ => Effect::Unknown,
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
fn listing(args: &[Arg], spec: &Listing) -> Effect {
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
                    iter.next();
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
        Effect::Changes
    } else if unknown {
        Effect::Unknown
    } else {
        Effect::ReadsOnly
    }
}

/// The table for PowerShell, by the cmdlet's name (an alias the guard knows
/// is already its cmdlet).
fn powershell(key: &str, unit: &Unit) -> Effect {
    match key {
        "get-childitem" | "get-content" | "select-string" | "get-item" | "get-location"
        | "test-path" | "resolve-path" | "write-output" | "write-host" | "where-object"
        | "select-object" | "sort-object" | "measure-object" | "cat" | "gc" | "type" | "sls"
        | "echo" | "pwd" => Effect::ReadsOnly,
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
        | "ren" => Effect::Changes,
        "git" => git(&unit.args),
        key if TOOLS.contains(&key) => Effect::Changes,
        _ => Effect::Unknown,
    }
}

/// The table for cmd.
fn cmd(key: &str, unit: &Unit) -> Effect {
    match key {
        "dir" | "type" | "findstr" | "echo" | "cd" | "chdir" => Effect::ReadsOnly,
        "del" | "erase" | "rd" | "rmdir" | "md" | "mkdir" | "copy" | "xcopy" | "move" | "ren"
        | "rename" | "robocopy" | "attrib" | "icacls" | "takeown" | "format" | "diskpart"
        | "reg" | "taskkill" | "shutdown" => Effect::Changes,
        "git" => git(&unit.args),
        key if TOOLS.contains(&key) => Effect::Changes,
        _ => Effect::Unknown,
    }
}
