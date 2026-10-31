//! The rules about code a line runs that it does not show: git's own
//! commands and config, awk, expect, `AppleScript`, compiled .NET.

use super::Checker;
use crate::unit::{has_flag, operands, Arg, Unit};
use crate::{Rule, Shell};

impl Checker<'_> {
    /// Git, and code run through awk, expect, `AppleScript` or .NET.
    pub(super) fn code(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let shell = unit.shell;
        match key {
            // Git.
            "git" => self.git(args),

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

    fn git(&mut self, args: &[Arg]) {
        let mut at = 0;
        let mut repository = None;
        let mut configs = Vec::new();
        while let Some(text) = args.get(at).and_then(Arg::known) {
            match text {
                "-C" => {
                    repository = args.get(at + 1);
                    at += 2;
                }
                "-c" => {
                    configs.extend(args.get(at + 1).and_then(Arg::known));
                    at += 2;
                }
                "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--config-env" => {
                    at += 2;
                }
                text if text.starts_with('-') => at += 1,
                _ => break,
            }
        }
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
        let (rule, reason) = match sub {
            "reset" if flag(None, Some("hard")) => {
                (Rule::GitDiscard, "throws away uncommitted changes")
            }
            "clean"
                if (force_needless || flag(Some('f'), Some("force")))
                    && !flag(Some('n'), Some("dry-run")) =>
            {
                (Rule::GitDiscard, "deletes untracked files")
            }
            "checkout"
                if flag(Some('f'), Some("force"))
                    || rest
                        .iter()
                        .position(|arg| arg.known() == Some("--"))
                        .is_some_and(|dashes| dashes + 1 < rest.len())
                    || operands.iter().any(|arg| arg.known() == Some(".")) =>
            {
                (Rule::GitDiscard, "throws away changes to files")
            }
            "restore" if !flag(Some('S'), Some("staged")) || flag(Some('W'), Some("worktree")) => {
                (Rule::GitDiscard, "throws away changes to files")
            }
            "switch" if flag(None, Some("discard-changes")) || flag(Some('f'), Some("force")) => {
                (Rule::GitDiscard, "throws away changes to files")
            }
            "stash" if matches!(first, Some("drop" | "clear")) => {
                (Rule::GitDiscard, "deletes stashed changes")
            }
            "branch"
                if flag(Some('D'), None)
                    || (flag(Some('d'), Some("delete")) && flag(Some('f'), Some("force"))) =>
            {
                (
                    Rule::GitDiscard,
                    "deletes a branch even if it is not merged",
                )
            }
            "push"
                if flag(Some('f'), Some("force"))
                    || flag(None, Some("force-with-lease"))
                    || flag(None, Some("force-if-includes"))
                    || flag(None, Some("mirror"))
                    || flag(Some('d'), Some("delete"))
                    || flag(None, Some("prune"))
                    || operands.iter().any(|arg| {
                        arg.known()
                            .is_some_and(|text| text.starts_with('+') || text.starts_with(':'))
                    }) =>
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
            "gc" if rest
                .iter()
                .any(|arg| matches!(arg.known(), Some("--prune=now" | "--prune=all"))) =>
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
            "update-ref" if flag(Some('d'), None) => (Rule::GitDiscard, "deletes a ref"),
            // A tag has no reflog to bring it back from.
            "tag" if flag(Some('d'), Some("delete")) => (Rule::GitDiscard, "deletes a tag"),
            "submodule" if first == Some("deinit") && flag(Some('f'), Some("force")) => {
                (Rule::GitDiscard, "throws away a submodule's changes")
            }
            "worktree" if first == Some("remove") && flag(Some('f'), Some("force")) => {
                (Rule::GitDiscard, "deletes a worktree with its changes")
            }
            _ => return,
        };
        self.add(rule, reason, repository);
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

/// A git option: as [`has_flag`], and also a long option abbreviated, as
/// git accepts (`--ha` is `--hard`); at least two letters.
fn git_flag(args: &[Arg], short: Option<char>, long: Option<&str>) -> bool {
    has_flag(args, short, long)
        || long.is_some_and(|long| {
            args.iter()
                .filter_map(Arg::known)
                .take_while(|text| *text != "--")
                .filter_map(|text| text.strip_prefix("--"))
                .map(|name| name.split('=').next().unwrap_or(name))
                .any(|name| name.len() >= 2 && long.starts_with(name))
        })
}
