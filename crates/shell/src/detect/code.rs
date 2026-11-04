//! The rules about code a line runs that it does not show: git's own
//! commands and config, awk, expect, `AppleScript`, compiled .NET.

use super::hedged;
use super::Checker;
use crate::launch::{git_global, git_long, is_submodule, Global};
use crate::said::Said;
use crate::unit::{could_be, has_flag, may_be_option, operands, unknown_start, Arg, Flagged, Unit};
use crate::{Rule, Shell};

impl Checker<'_> {
    /// Git, and code run through awk, expect, `AppleScript` or .NET.
    pub(super) fn code(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let shell = unit.shell;
        match key {
            // Git.
            "git" => self.git(args, shell),

            // Code the guard does not read.
            "add-type" => self.add(Rule::Unknown, "compiles and loads code", None),
            "expect" if shell == Shell::Posix => {
                self.add(
                    Rule::Unknown,
                    "runs expect code the guard does not read",
                    None,
                );
            }
            "awk" | "gawk" | "mawk" | "nawk" => self.awk(unit),
            "osascript" => self.add(
                Rule::Unknown,
                "runs AppleScript the guard does not read",
                None,
            ),
            _ => {}
        }
    }

    /// awk code that runs commands (`system(…)`, a pipe) or writes files
    /// (`print > "f"`) is risky; so is code the guard cannot read (`-f script`,
    /// a library `-i` or `@include` loads, a variable). gawk's `inplace`
    /// library (`-i inplace`) edits each file awk reads, so each is a write.
    fn awk(&mut self, unit: &Unit) {
        let args = unit.args.as_slice();
        let mut programs = Vec::new();
        let mut file = false;
        let mut libraries: Vec<Library<'_>> = Vec::new();
        let mut at = 0;
        while let Some(arg) = args.get(at) {
            at += 1;
            match arg.known() {
                Some("-f" | "--file" | "-E" | "--exec") => {
                    file = true;
                    at += 1;
                }
                Some("-e" | "--source") => {
                    programs.extend(args.get(at));
                    at += 1;
                }
                Some("-i" | "--include") => {
                    libraries.push(args.get(at).map_or(Library::Other, library));
                    at += 1;
                }
                Some("-F" | "-v" | "--field-separator" | "--assign" | "-l" | "--load") => at += 1,
                Some("--") => break,
                Some(text) if text.starts_with("--include=") => {
                    libraries.push(named_library(&text["--include=".len()..]));
                }
                Some(text) if text.starts_with("--file=") || text.starts_with("--exec=") => {
                    file = true;
                }
                Some(text) if text.starts_with("-i") && !text.starts_with("--") => {
                    libraries.push(named_library(&text[2..]));
                }
                Some(text) if text.starts_with("-f") || text.starts_with("-E") => file = true,
                Some(text) if text.len() > 1 && text.starts_with('-') => {}
                _ => {
                    at -= 1;
                    break;
                }
            }
        }
        let mut operands = args.get(at..).unwrap_or_default();
        if programs.is_empty() && !file {
            if let Some((program, rest)) = operands.split_first() {
                programs.push(program);
                operands = rest;
            }
        }
        if file {
            self.add(
                Rule::Unknown,
                "runs an awk script the guard does not read",
                None,
            );
        }
        for program in programs {
            match program.known() {
                Some(code) => {
                    if awk_runs_commands(code) {
                        self.add(
                            Rule::Unknown,
                            "runs commands or writes files from awk code",
                            None,
                        );
                    }
                    libraries.extend(included(code));
                }
                None => self.add(
                    Rule::Unknown,
                    "runs awk code only known when it runs",
                    Some(program),
                ),
            }
        }
        if libraries.iter().any(|library| *library != Library::InPlace) {
            self.add(
                Rule::Unknown,
                "runs an awk script the guard does not read",
                libraries.iter().find_map(|library| match library {
                    Library::Unread(arg) => Some(*arg),
                    _ => None,
                }),
            );
        }
        let in_place = if libraries.contains(&Library::InPlace) {
            Flagged::Written
        } else if libraries
            .iter()
            .any(|library| matches!(library, Library::Unread(_)))
        {
            Flagged::Unread
        } else {
            Flagged::Absent
        };
        // Each file awk reads, but `-` (its input) and an assignment
        // (`x=1`), which it reads as one.
        self.flagged(in_place, |checker| {
            for operand in operands.iter().filter(|operand| {
                !operand
                    .known()
                    .is_some_and(|text| text == "-" || assigns(text))
            }) {
                checker.write(unit.shell, unit.scope(), operand, "edits");
            }
        });
    }

    /// git's commands that throw work away. An argument only known when it
    /// runs that may be the option that makes one do so (`git push $F
    /// origin main`, `git push "-$F" origin main`, see [`may_be_option`])
    /// is taken as given, and the finding says it may (see [`hedged`]); an
    /// option that keeps work is taken only as written.
    fn git(&mut self, args: &[Arg], shell: Shell) {
        let Global {
            at,
            repository,
            configs,
        } = git_global(args);
        // A `-c` config value that makes git run a command of its own: an
        // alias body starting `!`, or a program git calls (pager, editor,
        // ssh, hooks).
        if configs.iter().any(|config| config_executes(config)) {
            self.add(
                Rule::Unknown,
                "runs a command through git config",
                repository,
            );
        }
        let Some(sub) = args.get(at).and_then(Arg::known) else {
            return;
        };
        let rest = &args[at + 1..];
        let flag = |short: Option<char>, long: Option<&str>| git_flag(rest, short, long);
        // Whether an argument only known when it runs may be the option.
        let unread = |short: Option<char>, long: Option<&str>| {
            may_be_option(rest, shell, |start| could_be(start, short, long))
        };
        // `git branch` and `git tag` refuse a delete beside a listing (`-l`,
        // and `-v` for a tag), so with one written, an argument only known
        // when it runs is no delete.
        let lists = flag(Some('l'), Some("list"));
        // `-c clean.requireForce=false` lets `clean` delete without `-f`.
        let force_needless = configs.iter().any(|config| {
            config.split_once('=').is_some_and(|(key, value)| {
                key.eq_ignore_ascii_case("clean.requireforce")
                    && matches!(
                        value.to_ascii_lowercase().as_str(),
                        "false" | "0" | "no" | "off"
                    )
            })
        });
        let operands = operands(rest, &[]);
        let first = operands.first().and_then(|arg| arg.known());
        // What a push that rewrites or deletes says, with `maybe` as below:
        // a force says to lease instead, and a lease alone (`git push
        // --force-with-lease`), which rewrites a branch only when nobody
        // pushed to it since, says so. A lease beside anything that forces,
        // deletes or is only known when it runs is read as a plain force,
        // with no advice: the lease is already written, and leasing a
        // delete still deletes.
        let push = |maybe: bool| -> Said {
            let forces = flag(Some('f'), Some("force"))
                || (maybe && unread(Some('f'), Some("force")))
                || operands.iter().any(|arg| refspec_starts(arg, shell, '+'));
            // Written as the lease, not as `--force`, which git also takes
            // as a prefix of `--force-with-lease` but reads as itself.
            let lease = rest
                .iter()
                .filter_map(Arg::known)
                .take_while(|text| *text != "--")
                .any(|text| text.starts_with("--force-w"));
            let deletes = flag(None, Some("mirror"))
                || flag(Some('d'), Some("delete"))
                || flag(None, Some("prune"))
                || operands.iter().any(|arg| refspec_starts(arg, shell, ':'));
            let leased = lease
                && !unread(Some('f'), Some("force"))
                && !deletes
                && operands.iter().all(|arg| arg.known().is_some());
            if forces {
                if lease || deletes {
                    REWRITES.into()
                } else {
                    Said::instead(REWRITES, "use `git push --force-with-lease`")
                }
            } else if leased {
                "rewrites a branch on the remote unless someone pushed since".into()
            } else {
                REWRITES.into()
            }
        };
        // Whether git's own options move it to another repository, where a
        // dry run typed in this folder would list something else.
        let elsewhere = args[..at].iter().filter_map(Arg::known).any(|text| {
            text == "-C" || text.starts_with("--git-dir") || text.starts_with("--work-tree")
        });
        // What the line does with the options it shows, or, with `maybe`,
        // with an argument only known when it runs taken as an option that
        // throws work away.
        let judge = |maybe: bool| -> Option<(Rule, Said)> {
            let may = |short: Option<char>, long: Option<&str>| {
                flag(short, long) || (maybe && unread(short, long))
            };
            let deletes = |short: Option<char>, long: Option<&str>, listing: bool| {
                flag(short, long) || (maybe && !listing && unread(short, long))
            };
            Some(match sub {
                "reset" if may(None, Some("hard")) => (
                    Rule::GitDiscard,
                    Said::instead("throws away uncommitted changes", STASH_FIRST),
                ),
                "clean"
                    if (force_needless || may(Some('f'), Some("force"))) && !git_dry_run(rest) =>
                {
                    (
                        Rule::GitDiscard,
                        Said::instead(
                            "deletes untracked files",
                            match clean_dry_run(rest) {
                                Some(dry) if !elsewhere => {
                                    format!("list what would go first (`{dry}`)")
                                }
                                _ => CLEAN_SAME.to_string(),
                            },
                        ),
                    )
                }
                "checkout"
                    if may(Some('f'), Some("force"))
                        || rest
                            .iter()
                            .position(|arg| arg.known() == Some("--"))
                            .is_some_and(|dashes| dashes + 1 < rest.len())
                        || operands.iter().any(|arg| arg.known() == Some(".")) =>
                {
                    (Rule::GitDiscard, Said::instead(CHANGES, STASH_FIRST))
                }
                "restore"
                    if !flag(Some('S'), Some("staged")) || may(Some('W'), Some("worktree")) =>
                {
                    (Rule::GitDiscard, Said::instead(CHANGES, STASH_FIRST))
                }
                "switch" if may(None, Some("discard-changes")) || may(Some('f'), Some("force")) => {
                    (Rule::GitDiscard, Said::instead(CHANGES, STASH_FIRST))
                }
                "stash" if matches!(first, Some("drop" | "clear")) => {
                    (Rule::GitDiscard, "deletes stashed changes".into())
                }
                "branch"
                    if deletes(Some('D'), None, lists)
                        || (flag(Some('d'), Some("delete")) && flag(Some('f'), Some("force"))) =>
                {
                    (
                        Rule::GitDiscard,
                        Said::instead(
                            "deletes a branch even if it is not merged",
                            "use `git branch -d`, which keeps a branch that is not merged",
                        ),
                    )
                }
                "push"
                    if may(Some('f'), Some("force"))
                        || flag(None, Some("force-with-lease"))
                        || flag(None, Some("force-if-includes"))
                        || flag(None, Some("mirror"))
                        || flag(Some('d'), Some("delete"))
                        || flag(None, Some("prune"))
                        || operands.iter().any(|arg| forced_refspec(arg, shell)) =>
                {
                    (Rule::GitRemote, push(maybe))
                }
                "filter-branch" | "filter-repo" => {
                    (Rule::GitHistory, "rewrites the repository's history".into())
                }
                "reflog" if matches!(first, Some("expire" | "delete")) => (
                    Rule::GitHistory,
                    "removes what git keeps to undo mistakes".into(),
                ),
                "gc" if (maybe && unread(None, Some("prune")))
                    || rest.iter().filter_map(Arg::known).any(|text| {
                        text.split_once('=').is_some_and(|(name, value)| {
                            matches!(value, "now" | "all") && git_long(name, "prune")
                        })
                    }) =>
                {
                    (
                        Rule::GitHistory,
                        "removes what git keeps to undo mistakes".into(),
                    )
                }
                "config" if config_set_executes(rest) => {
                    let alias = operands
                        .iter()
                        .filter_map(|arg| arg.known())
                        .find(|word| *word != "set")
                        .is_some_and(|key| key.to_ascii_lowercase().starts_with("alias."));
                    if alias {
                        (Rule::Unknown, "sets a git alias that runs a command".into())
                    } else {
                        (
                            Rule::SystemSettings,
                            "sets git config that runs a program".into(),
                        )
                    }
                }
                "update-ref" if may(Some('d'), None) => (Rule::GitDiscard, "deletes a ref".into()),
                // A tag has no reflog to bring it back from.
                "tag"
                    if deletes(
                        Some('d'),
                        Some("delete"),
                        lists || flag(Some('v'), Some("verify")),
                    ) =>
                {
                    (Rule::GitDiscard, "deletes a tag".into())
                }
                // A tag given again by force moves; where it pointed is gone.
                "tag"
                    if flag(Some('f'), Some("force"))
                        && !operands.is_empty()
                        && !flag(Some('l'), Some("list"))
                        && !flag(Some('v'), Some("verify")) =>
                {
                    (
                        Rule::GitDiscard,
                        "moves a tag, losing where it pointed".into(),
                    )
                }
                sub if is_submodule(sub)
                    && first == Some("update")
                    && may(Some('f'), Some("force")) =>
                {
                    (Rule::GitDiscard, "throws away changes in submodules".into())
                }
                sub if is_submodule(sub)
                    && first == Some("deinit")
                    && may(Some('f'), Some("force")) =>
                {
                    (Rule::GitDiscard, "throws away a submodule's changes".into())
                }
                "worktree" if first == Some("remove") && may(Some('f'), Some("force")) => (
                    Rule::GitDiscard,
                    "deletes a worktree with its changes".into(),
                ),
                _ => return None,
            })
        };
        if let Some((rule, said)) = judge(false) {
            self.add(rule, said, repository);
        } else if let Some((rule, said)) = judge(true) {
            let said = Said {
                reason: hedged(&said.reason),
                ..said
            };
            self.add(rule, said, repository);
        }
    }
}

/// What a push that rewrites or deletes says, when nothing better is known.
const REWRITES: &str = "rewrites or deletes branches on the remote";

/// What to do instead of a `git clean` that deletes, when the dry run
/// cannot be spelled out from the line: it moves git to another repository,
/// or an argument that may be an option is only known when it runs.
const CLEAN_SAME: &str = "list what would go first with `git clean -n` and the same options";

/// What to do instead of throwing changes away.
const STASH_FIRST: &str = "stash the changes first (`git stash`)";

/// What a checkout, restore or switch that throws changes away says.
const CHANGES: &str = "throws away changes to files";

/// Whether a `git push` operand is a refspec that forces (`+main`) or
/// deletes (`:main`) a branch on the remote (see [`refspec_starts`]).
fn forced_refspec(arg: &Arg, shell: Shell) -> bool {
    refspec_starts(arg, shell, '+') || refspec_starts(arg, shell, ':')
}

/// Whether a `git push` operand starts with `start`: written so, or only
/// known when it runs and starting so (`"+$B"`), whatever the rest holds.
fn refspec_starts(arg: &Arg, shell: Shell, start: char) -> bool {
    match arg.known() {
        Some(text) => text.starts_with(start),
        None => unknown_start(arg, shell).is_some_and(|text| text.starts_with(start)),
    }
}

/// The dry run of a `git clean` that deletes: `git clean -n`, with the `-d`,
/// `-x` and `-X` it is given, so it lists what the same clean would delete
/// in its folders and among the ignored files. Its options are read as
/// [`git_dry_run`] reads them: the value of `-e`/`--exclude` is a pattern.
/// `None` when an argument before `--` is only known when it runs, since it
/// may hold a `-d` or `-x` the dry run would then leave out.
fn clean_dry_run(args: &[Arg]) -> Option<String> {
    let mut options = String::from("n");
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        let text = arg.known()?;
        if text == "--" {
            break;
        }
        if text.starts_with("--") {
            if !text.contains('=') && git_long(text, "exclude") {
                words.next();
            }
        } else if let Some(bundle) = text.strip_prefix('-') {
            if !bundle.starts_with(|c: char| c.is_ascii_alphabetic()) {
                continue;
            }
            let (flags, pattern) = bundle.split_once('e').unwrap_or((bundle, ""));
            for short in flags.chars().filter(|c| matches!(c, 'd' | 'x' | 'X')) {
                if !options.contains(short) {
                    options.push(short);
                }
            }
            if bundle.contains('e') && pattern.is_empty() {
                words.next();
            }
        }
    }
    Some(format!("git clean -{options}"))
}

/// A library awk loads with `-i`, `--include` or `@include`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Library<'a> {
    /// gawk's `inplace`, which edits each file awk reads.
    InPlace,
    /// Any other, which the guard does not read.
    Other,
    /// One only known when it runs, which may be either.
    Unread(&'a Arg),
}

/// The library an `-i` argument names.
fn library(arg: &Arg) -> Library<'_> {
    match arg.known() {
        Some(name) => named_library(name),
        None => Library::Unread(arg),
    }
}

/// The library `name` is: gawk finds `inplace` as `inplace.awk` in its own
/// folder.
fn named_library(name: &str) -> Library<'static> {
    if matches!(name, "inplace" | "inplace.awk") {
        Library::InPlace
    } else {
        Library::Other
    }
}

/// The libraries awk code loads with `@include "name"`: one whose name is
/// not a plain string is one the guard does not read.
fn included(code: &str) -> Vec<Library<'static>> {
    code.split("@include")
        .skip(1)
        .map(|after| {
            after
                .trim_start()
                .strip_prefix('"')
                .and_then(|name| name.split_once('"'))
                .map_or(Library::Other, |(name, _)| named_library(name))
        })
        .collect()
}

/// Whether an awk operand is an assignment (`x=1`, `ns::x=1`), which awk
/// reads as one and not as a file.
fn assigns(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':')
    })
}

/// Whether awk code runs a command or writes a file: `system`, a single
/// `|` (`"cmd" | getline`, `print | "sh"`; `||` is a logical or), or `>`
/// into a quoted file other than `/dev/stdout` or `/dev/stderr`.
fn awk_runs_commands(code: &str) -> bool {
    if code.contains("system") {
        return true;
    }
    let bytes = code.as_bytes();
    bytes.iter().enumerate().any(|(at, &byte)| {
        let before = at
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .copied();
        let after = bytes.get(at + 1).copied();
        match byte {
            b'|' => before != Some(b'|') && after != Some(b'|'),
            b'>' if before != Some(b'>') && after != Some(b'=') => code[at + 1..]
                .trim_start_matches('>')
                .trim_start()
                .strip_prefix('"')
                .is_some_and(|target| !target.starts_with("/dev/std")),
            _ => false,
        }
    })
}

/// Whether a git config `key=value` makes git run a command: an alias body
/// starting `!`, or a key whose value git executes.
fn config_executes(config: &str) -> bool {
    let Some((key, value)) = config.split_once('=') else {
        return false;
    };
    let key = key.trim().to_ascii_lowercase();
    if let Some(alias) = key.strip_prefix("alias.") {
        return !alias.is_empty() && value.trim_start().starts_with('!');
    }
    EXEC_CONFIG_KEYS.contains(&key.as_str())
}

/// Whether a `git config KEY VALUE` sets one of those keys.
fn config_set_executes(rest: &[Arg]) -> bool {
    let reads = rest.iter().filter_map(Arg::known).any(|text| {
        matches!(
            text,
            "--get"
                | "--get-all"
                | "--get-regexp"
                | "--get-urlmatch"
                | "--list"
                | "-l"
                | "--unset"
                | "--unset-all"
                | "--remove-section"
                | "--rename-section"
                | "--edit"
                | "-e"
        )
    });
    if reads {
        return false;
    }
    let operands = operands(rest, &["--file", "-f", "--blob", "--type", "--default"]);
    let mut words = operands.iter().filter_map(|arg| arg.known());
    // `git config set KEY VALUE` (git 2.46) or `git config KEY VALUE`; the
    // other subcommands and a key alone only read.
    let (key, value) = match words.next() {
        Some("set") => (words.next(), words.next()),
        Some("get" | "unset" | "list" | "edit" | "rename-section" | "remove-section") => {
            return false;
        }
        key => (key, words.next()),
    };
    match (key, value) {
        (Some(key), Some(value)) => config_executes(&format!("{key}={value}")),
        _ => false,
    }
}

/// git config keys whose value git runs as a command.
const EXEC_CONFIG_KEYS: [&str; 11] = [
    "core.pager",
    "core.editor",
    "core.sshcommand",
    "core.fsmonitor",
    "core.hookspath",
    "core.askpass",
    "sequence.editor",
    "diff.external",
    "credential.helper",
    "gpg.program",
    "uploadpack.packobjectshook",
];

/// Whether `git clean` is left a dry run by its options. git reads them in
/// order, so the last of `-n`, `--dry-run` and `--no-dry-run` wins, each
/// also given as a prefix (`--dry`, `--no-d`); a prefix of `--no-` names
/// several options, so git refuses it, and it is read as a dry run off. The
/// value of `-e`/`--exclude` is not an option: in `-enx` and in `-e -n` the
/// `n` is a pattern.
fn git_dry_run(args: &[Arg]) -> bool {
    let mut dry = false;
    let mut words = args.iter().filter_map(Arg::known);
    while let Some(text) = words.next() {
        if text == "--" {
            break;
        }
        if text.starts_with("--") {
            if git_long(text, "dry-run") {
                dry = true;
            } else if git_long(text, "no-dry-run") {
                dry = false;
            } else if !text.contains('=') && git_long(text, "exclude") {
                words.next();
            }
        } else if let Some(bundle) = text.strip_prefix('-') {
            if !bundle.starts_with(|c: char| c.is_ascii_alphabetic()) {
                continue;
            }
            let (options, pattern) = bundle.split_once('e').unwrap_or((bundle, ""));
            if options.contains('n') {
                dry = true;
            }
            if bundle.contains('e') && pattern.is_empty() {
                words.next();
            }
        }
    }
    dry
}

/// A git option: as [`has_flag`], and also a long option given as a prefix
/// of it, as git takes one (`--h` is `--hard`, see [`git_long`]).
fn git_flag(args: &[Arg], short: Option<char>, long: Option<&str>) -> bool {
    has_flag(args, short, long)
        || long.is_some_and(|long| {
            args.iter()
                .filter_map(Arg::known)
                .take_while(|text| *text != "--")
                .any(|text| git_long(text, long))
        })
}
