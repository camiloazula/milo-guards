//! The rules about code a line runs that it does not show: git's own
//! commands and config, awk, expect, `AppleScript`, compiled .NET.

use super::hedged;
use super::Checker;
use crate::launch::{git_global, git_long, is_submodule, Global};
use crate::unit::{could_be, has_flag, may_be_option, operands, unknown_start, Arg, Unit};
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
            "awk" | "gawk" | "mawk" | "nawk" => self.awk(args),
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
    /// a variable).
    fn awk(&mut self, args: &[Arg]) {
        let mut programs = Vec::new();
        let mut file = false;
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.known() {
                Some("-f" | "--file") => {
                    file = true;
                    iter.next();
                }
                Some("-e" | "--source") => programs.extend(iter.next()),
                Some(
                    "-F" | "-v" | "--field-separator" | "--assign" | "-i" | "--include" | "-l"
                    | "--load",
                ) => {
                    iter.next();
                }
                Some("--") => {
                    programs.extend(iter.next());
                    break;
                }
                Some(text) if text.len() > 1 && text.starts_with('-') => {}
                _ => {
                    if programs.is_empty() && !file {
                        programs.push(arg);
                    }
                    break;
                }
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
                Some(code) if awk_runs_commands(code) => self.add(
                    Rule::Unknown,
                    "runs commands or writes files from awk code",
                    None,
                ),
                Some(_) => {}
                None => self.add(
                    Rule::Unknown,
                    "runs awk code only known when it runs",
                    Some(program),
                ),
            }
        }
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
        // What the line does with the options it shows, or, with `maybe`,
        // with an argument only known when it runs taken as an option that
        // throws work away.
        let judge = |maybe: bool| -> Option<(Rule, &'static str)> {
            let may = |short: Option<char>, long: Option<&str>| {
                flag(short, long) || (maybe && unread(short, long))
            };
            let deletes = |short: Option<char>, long: Option<&str>, listing: bool| {
                flag(short, long) || (maybe && !listing && unread(short, long))
            };
            Some(match sub {
                "reset" if may(None, Some("hard")) => {
                    (Rule::GitDiscard, "throws away uncommitted changes")
                }
                "clean"
                    if (force_needless || may(Some('f'), Some("force"))) && !git_dry_run(rest) =>
                {
                    (Rule::GitDiscard, "deletes untracked files")
                }
                "checkout"
                    if may(Some('f'), Some("force"))
                        || rest
                            .iter()
                            .position(|arg| arg.known() == Some("--"))
                            .is_some_and(|dashes| dashes + 1 < rest.len())
                        || operands.iter().any(|arg| arg.known() == Some(".")) =>
                {
                    (Rule::GitDiscard, "throws away changes to files")
                }
                "restore"
                    if !flag(Some('S'), Some("staged")) || may(Some('W'), Some("worktree")) =>
                {
                    (Rule::GitDiscard, "throws away changes to files")
                }
                "switch" if may(None, Some("discard-changes")) || may(Some('f'), Some("force")) => {
                    (Rule::GitDiscard, "throws away changes to files")
                }
                "stash" if matches!(first, Some("drop" | "clear")) => {
                    (Rule::GitDiscard, "deletes stashed changes")
                }
                "branch"
                    if deletes(Some('D'), None, lists)
                        || (flag(Some('d'), Some("delete")) && flag(Some('f'), Some("force"))) =>
                {
                    (
                        Rule::GitDiscard,
                        "deletes a branch even if it is not merged",
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
                    (
                        Rule::GitRemote,
                        "rewrites or deletes branches on the remote",
                    )
                }
                "filter-branch" | "filter-repo" => {
                    (Rule::GitHistory, "rewrites the repository's history")
                }
                "reflog" if matches!(first, Some("expire" | "delete")) => {
                    (Rule::GitHistory, "removes what git keeps to undo mistakes")
                }
                "gc" if (maybe && unread(None, Some("prune")))
                    || rest.iter().filter_map(Arg::known).any(|text| {
                        text.split_once('=').is_some_and(|(name, value)| {
                            matches!(value, "now" | "all") && git_long(name, "prune")
                        })
                    }) =>
                {
                    (Rule::GitHistory, "removes what git keeps to undo mistakes")
                }
                "config" if config_set_executes(rest) => {
                    let alias = operands
                        .iter()
                        .filter_map(|arg| arg.known())
                        .find(|word| *word != "set")
                        .is_some_and(|key| key.to_ascii_lowercase().starts_with("alias."));
                    if alias {
                        (Rule::Unknown, "sets a git alias that runs a command")
                    } else {
                        (Rule::SystemSettings, "sets git config that runs a program")
                    }
                }
                "update-ref" if may(Some('d'), None) => (Rule::GitDiscard, "deletes a ref"),
                // A tag has no reflog to bring it back from.
                "tag"
                    if deletes(
                        Some('d'),
                        Some("delete"),
                        lists || flag(Some('v'), Some("verify")),
                    ) =>
                {
                    (Rule::GitDiscard, "deletes a tag")
                }
                // A tag given again by force moves; where it pointed is gone.
                "tag"
                    if flag(Some('f'), Some("force"))
                        && !operands.is_empty()
                        && !flag(Some('l'), Some("list"))
                        && !flag(Some('v'), Some("verify")) =>
                {
                    (Rule::GitDiscard, "moves a tag, losing where it pointed")
                }
                sub if is_submodule(sub)
                    && first == Some("update")
                    && may(Some('f'), Some("force")) =>
                {
                    (Rule::GitDiscard, "throws away changes in submodules")
                }
                sub if is_submodule(sub)
                    && first == Some("deinit")
                    && may(Some('f'), Some("force")) =>
                {
                    (Rule::GitDiscard, "throws away a submodule's changes")
                }
                "worktree" if first == Some("remove") && may(Some('f'), Some("force")) => {
                    (Rule::GitDiscard, "deletes a worktree with its changes")
                }
                _ => return None,
            })
        };
        if let Some((rule, reason)) = judge(false) {
            self.add(rule, reason, repository);
        } else if let Some((rule, reason)) = judge(true) {
            self.add(rule, hedged(reason), repository);
        }
    }
}

/// Whether a `git push` operand is a refspec that forces (`+main`) or
/// deletes (`:main`) a branch on the remote: written so, or only known when
/// it runs and starting so (`"+$B"`, `":$B"`), whatever the rest holds.
fn forced_refspec(arg: &Arg, shell: Shell) -> bool {
    let forced = |text: &str| text.starts_with('+') || text.starts_with(':');
    match arg.known() {
        Some(text) => forced(text),
        None => unknown_start(arg, shell).is_some_and(|text| forced(&text)),
    }
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
