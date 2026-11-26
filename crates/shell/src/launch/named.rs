//! The commands a program runs that the line names in a variable it sets or
//! in an option, beside what the program does itself: `GIT_SSH_COMMAND='…'
//! git fetch`, `PAGER='…' git log`, `ssh -o ProxyCommand='…' host`, `git
//! rebase -x '…'`, `fd -x cmd`, `sort --compress-program=prog`. Each is read
//! as a command line of the shell the program hands it to, as `rsync -e` and
//! `man -P` are, and judged by every rule.

use super::git::{global as git_global, is_long as git_long};
use super::{shell_word, Launch};
use std::collections::HashSet;

use crate::unit::{self, Arg, Split, Unit};
use crate::{Rule, Shell};

/// How a program runs the command a variable or an option names.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Through {
    /// With a POSIX `sh`, on Windows too: git runs every command through
    /// the `sh` Git for Windows ships, and the POSIX tools ported to
    /// Windows (rsync, less, man) through theirs.
    Posix,
    /// With the system's shell: `sh` on a POSIX line, `cmd` on a Windows
    /// one (PowerShell's or cmd's).
    System,
}

/// What the value of a variable or an option is.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Value {
    /// A command line, handed to a shell (`GIT_SSH_COMMAND`, `PAGER`).
    Line,
    /// A program, run by its name with no shell (`GIT_SSH`,
    /// `--compress-program`): read as a line of that one word.
    Program,
    /// `less`'s input preprocessor: a command line after the `|`, `||` or
    /// `-` that say how less reads its output (`LESSOPEN='|lesspipe %s'`).
    Preprocessor,
}

/// Programs that read the same variables: their names as the guard keys
/// them, the variables with what each value is, and how they run it.
type Programs = (
    &'static [&'static str],
    &'static [(&'static str, Value)],
    Through,
);

/// The variables whose value a program runs, by program: its name as the
/// guard keys it, the variables it reads, and how it runs them. Only the
/// variables a program reads as a command or a program to start are here,
/// from each one's documentation; one that names a file of settings
/// (`GIT_CONFIG_GLOBAL`), a folder of programs (`GIT_EXEC_PATH`) or the
/// options of the program itself (`LESS`, `TAR_OPTIONS`) is not.
const VARIABLES: &[Programs] = &[
    (
        &["git"],
        &[
            ("GIT_SSH_COMMAND", Value::Line),
            ("GIT_SSH", Value::Program),
            ("GIT_PAGER", Value::Line),
            ("PAGER", Value::Line),
            ("GIT_EDITOR", Value::Line),
            ("GIT_SEQUENCE_EDITOR", Value::Line),
            ("VISUAL", Value::Line),
            ("EDITOR", Value::Line),
            ("GIT_EXTERNAL_DIFF", Value::Line),
            ("GIT_ASKPASS", Value::Line),
            ("SSH_ASKPASS", Value::Line),
            ("GIT_PROXY_COMMAND", Value::Line),
        ],
        Through::Posix,
    ),
    (
        &["rsync"],
        &[
            ("RSYNC_RSH", Value::Line),
            ("RSYNC_CONNECT_PROG", Value::Line),
        ],
        Through::Posix,
    ),
    (
        &["less"],
        &[
            ("LESSOPEN", Value::Preprocessor),
            ("LESSCLOSE", Value::Preprocessor),
        ],
        Through::Posix,
    ),
    (
        &["man"],
        &[
            ("MANPAGER", Value::Line),
            ("PAGER", Value::Line),
            ("BROWSER", Value::Line),
        ],
        Through::Posix,
    ),
    (
        &["crontab", "vipw", "vigr"],
        &[("VISUAL", Value::Line), ("EDITOR", Value::Line)],
        Through::Posix,
    ),
    (
        &["visudo", "sudoedit"],
        &[
            ("SUDO_EDITOR", Value::Line),
            ("VISUAL", Value::Line),
            ("EDITOR", Value::Line),
        ],
        Through::Posix,
    ),
    (
        &["systemctl"],
        &[
            ("SYSTEMD_PAGER", Value::Line),
            ("PAGER", Value::Line),
            ("SYSTEMD_EDITOR", Value::Line),
            ("EDITOR", Value::Line),
            ("VISUAL", Value::Line),
        ],
        Through::Posix,
    ),
    (
        &[
            "journalctl",
            "loginctl",
            "busctl",
            "coredumpctl",
            "networkctl",
            "resolvectl",
            "machinectl",
            "localectl",
            "timedatectl",
            "bootctl",
            "homectl",
            "userdbctl",
            "systemd-analyze",
        ],
        &[("SYSTEMD_PAGER", Value::Line), ("PAGER", Value::Line)],
        Through::Posix,
    ),
    (
        &[
            "ssh",
            "slogin",
            "scp",
            "sftp",
            "autossh",
            "ssh-add",
            "ssh-copy-id",
            "sshfs",
        ],
        &[("SSH_ASKPASS", Value::Line)],
        Through::System,
    ),
    (
        &["gh"],
        &[
            ("GH_PAGER", Value::Line),
            ("PAGER", Value::Line),
            ("GH_EDITOR", Value::Line),
            ("VISUAL", Value::Line),
            ("EDITOR", Value::Line),
            ("GH_BROWSER", Value::Line),
            ("BROWSER", Value::Line),
        ],
        Through::System,
    ),
    (
        &["aws"],
        &[("AWS_PAGER", Value::Line), ("PAGER", Value::Line)],
        Through::System,
    ),
    (
        &["kubectl"],
        &[("KUBE_EDITOR", Value::Line), ("EDITOR", Value::Line)],
        Through::System,
    ),
    (
        &["bat"],
        &[("BAT_PAGER", Value::Line), ("PAGER", Value::Line)],
        Through::System,
    ),
    (
        &["svn"],
        &[
            ("SVN_EDITOR", Value::Line),
            ("VISUAL", Value::Line),
            ("EDITOR", Value::Line),
            ("SVN_SSH", Value::Line),
        ],
        Through::System,
    ),
    (
        &["hg"],
        &[
            ("HGEDITOR", Value::Line),
            ("VISUAL", Value::Line),
            ("EDITOR", Value::Line),
            ("HGMERGE", Value::Line),
            ("PAGER", Value::Line),
        ],
        Through::System,
    ),
];

/// The variables that make every program the line starts load a library
/// first: the dynamic linker's `LD_PRELOAD` and `LD_AUDIT`, and macOS's
/// `DYLD_INSERT_LIBRARIES`. A search path (`LD_LIBRARY_PATH`) is not one.
const LIBRARIES: [&str; 3] = ["LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES"];

/// The library the line tells the program of `unit` to load first, in one of
/// [`LIBRARIES`]: the value as written, or as the line spells it when only
/// known when it runs. An empty value loads none.
pub(super) fn loaded_library(unit: &Unit) -> Option<String> {
    unit.argument_variables
        .newest_first()
        .filter(|(name, _)| LIBRARIES.contains(&name.as_str()))
        .find(|(_, value)| {
            !matches!(value, Arg::Null) && value.known().is_none_or(|text| !text.trim().is_empty())
        })
        .map(|(_, value)| value.text().to_string())
}

/// The name of a variable of [`VARIABLES`] that `name` is, written in any
/// case, as Windows reads the names of variables: the one a program reads.
pub(crate) fn command_variable(name: &str) -> Option<&'static str> {
    VARIABLES
        .iter()
        .flat_map(|(_, variables, _)| variables.iter())
        .map(|(variable, _)| *variable)
        .chain(LIBRARIES)
        .find(|variable| variable.eq_ignore_ascii_case(name))
}

/// Whether `name`, as a POSIX shell writes it, is a variable of
/// [`VARIABLES`].
pub(crate) fn is_command_variable(name: &str) -> bool {
    command_variable(name) == Some(name)
}

/// `launched`, what the program `key` of `unit` does, with the commands the
/// line names for it in a variable it sets or an option run besides (see
/// [`commands`]). A value the line sets once may be read at every program
/// that reads it, so those readings are bounded as a line's own text is:
/// past it, the line is unreadable.
pub(super) fn with_commands(split: &mut Split, key: &str, unit: &Unit, launched: Launch) -> Launch {
    let Named {
        shell,
        commands: named,
        too_many,
        libraries,
    } = commands(key, unit);
    if too_many {
        split.problem(Rule::Unreadable, TOO_MANY, None);
    }
    for library in libraries {
        split.problem(
            Rule::Unknown,
            "loads a library into the program",
            Some(library.text()),
        );
    }
    let mut lines = Vec::new();
    for (line, variable) in named {
        if variable {
            if let Some(text) = line.known() {
                if !unit::read_variable_command(split, text.len().max(LEAST_READ) + 1) {
                    break;
                }
            }
        }
        lines.push(line);
    }
    if lines.is_empty() {
        return launched;
    }
    besides(launched, shell, lines)
}

/// `launched` with `lines` run through `shell` besides.
fn besides(launched: Launch, shell: Shell, mut lines: Vec<Arg>) -> Launch {
    match launched {
        Launch::Itself => Launch::Commands {
            shell,
            commands: lines,
            moves: false,
        },
        Launch::Commands {
            shell: own,
            mut commands,
            moves,
        } if own == shell => {
            commands.append(&mut lines);
            Launch::Commands {
                shell,
                commands,
                moves,
            }
        }
        Launch::In(folder, folder_shell, inner) => Launch::In(
            folder,
            folder_shell,
            Box::new(besides(*inner, shell, lines)),
        ),
        other => Launch::Either(
            Box::new(other),
            Box::new(Launch::Commands {
                shell,
                commands: lines,
                moves: false,
            }),
        ),
    }
}

/// The shell the program of `unit` runs what `through` says through.
fn shell_of(through: Through, unit: &Unit) -> Shell {
    match (through, unit.shell) {
        (Through::System, Shell::PowerShell | Shell::Cmd) => Shell::Cmd,
        _ => Shell::Posix,
    }
}

/// The commands a program runs that the line names, and the shell it hands
/// them to.
struct Named {
    shell: Shell,
    /// Each command, with whether a variable named it.
    commands: Vec<(Arg, bool)>,
    /// Whether the variables gave it more values than the guard reads.
    too_many: bool,
    /// The libraries its options tell it to load (`ssh -I lib.so`).
    libraries: Vec<Arg>,
}

/// The most values the line may give the variables one program reads: each
/// is a command it may run, and a line that sets them again and again would
/// have every value read at every program. Past it, the line is
/// unreadable.
const MOST_VALUES: usize = 64;

/// What reading a command a variable sets costs of the budget of such
/// readings at the least, in bytes: even a short one is a parse of its
/// own, so a line that runs it at every program of thousands is stopped
/// after about a thousand.
const LEAST_READ: usize = 64;

/// Why a line is unreadable past [`MOST_VALUES`] or past the bound on what
/// the commands variables set are read for.
const TOO_MANY: &str = "runs the command a variable sets too many times to read";

/// The commands the program `key` of `unit` runs that the line names, each
/// with whether a variable named it, and the shell it hands them to.
fn commands(key: &str, unit: &Unit) -> Named {
    // `sudo -e` runs the editor `sudoedit` runs.
    let key = if key == "sudo" && super::sudo_edits(&unit.args).is_some() {
        "sudoedit"
    } else {
        key
    };
    let mut found = Vec::new();
    let mut through = Through::System;
    let mut libraries = Vec::new();
    let mut seen = HashSet::new();
    let mut given = 0;
    let mut too_many = false;
    for (programs, variables, how) in VARIABLES {
        if !programs.contains(&key) {
            continue;
        }
        through = *how;
        for (name, value) in unit.argument_variables.iter() {
            let Some(&(_, kind)) = variables.iter().find(|(variable, _)| variable == name) else {
                continue;
            };
            given += 1;
            if given > MOST_VALUES {
                too_many = true;
                break;
            }
            // An empty value, or PowerShell's `$null`, which removes the
            // variable, names no command: the program runs its own. A value
            // the line gives again is read once.
            if matches!(value, Arg::Null)
                || value.known().is_some_and(|text| text.trim().is_empty())
                || !seen.insert((kind, value.known().is_some(), value.text()))
            {
                continue;
            }
            found.push((read_value(value, kind), true));
        }
    }
    let options = match key {
        "git" => {
            through = Through::Posix;
            git_options(&unit.args)
        }
        "ssh" | "slogin" | "scp" | "sftp" | "autossh" | "ssh-copy-id" => {
            libraries.extend(ssh_libraries(key, &unit.args));
            ssh_options(key, &unit.args)
        }
        "sshfs" => sshfs_options(&unit.args),
        "mosh" => values_of(&unit.args, None, |text| text == "--ssh", "", &[]),
        "sort" if unit.shell == Shell::Posix => sort_options(&unit.args),
        "less" if unit.shell != Shell::Cmd => {
            through = Through::Posix;
            less_options(&unit.args)
        }
        "rg" => rg_options(&unit.args),
        _ => Vec::new(),
    };
    found.extend(options.into_iter().map(|line| (line, false)));
    Named {
        shell: shell_of(through, unit),
        commands: found,
        too_many,
        libraries,
    }
}

/// The command line a value of `kind` is: a line as it is, a program as a
/// line of that one word, a preprocessor's line after the marks that say
/// how less reads it. A value only known when it runs stays one.
fn read_value(value: &Arg, kind: Value) -> Arg {
    let Some(text) = value.known() else {
        return value.clone();
    };
    match kind {
        Value::Line => Arg::Known(text.to_string()),
        Value::Program => Arg::Known(shell_word(text)),
        Value::Preprocessor => {
            Arg::Known(text.trim_start().trim_start_matches(['|', '-']).to_string())
        }
    }
}

/// The values of an option, as a program that reads its options as
/// `getopt` does gives them, before a `--`: `-x VALUE` and `-xVALUE` (also
/// at the end of a bundle, `-ix VALUE`) for `letter`, `--name VALUE` and
/// `--name=VALUE` for a long name `long` says is the one (git takes a
/// prefix of it). `short` are the other letters that take a value, whose
/// value is skipped; a long option of `long_values` takes the next word
/// unless its value follows `=`.
fn values_of(
    args: &[Arg],
    letter: Option<char>,
    long: impl Fn(&str) -> bool,
    short: &str,
    long_values: &[&str],
) -> Vec<Arg> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        if let Some(name) = text.strip_prefix("--") {
            let (name, joined) = name
                .split_once('=')
                .map_or((name, None), |(name, value)| (name, Some(value)));
            if !name.is_empty() && long(&format!("--{name}")) {
                if let Some(value) = joined {
                    found.push(Arg::Known(value.to_string()));
                } else {
                    found.extend(args.get(at).cloned());
                    at += 1;
                }
            } else if joined.is_none() && long_values.contains(&name) {
                at += 1;
            }
            continue;
        }
        let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty()) else {
            continue;
        };
        for (index, found_letter) in bundle.char_indices() {
            let rest = &bundle[index + found_letter.len_utf8()..];
            if Some(found_letter) == letter {
                if rest.is_empty() {
                    found.extend(args.get(at).cloned());
                    at += 1;
                } else {
                    found.push(Arg::Known(rest.to_string()));
                }
                break;
            }
            if short.contains(found_letter) {
                at += usize::from(rest.is_empty());
                break;
            }
        }
    }
    found
}

/// The commands git's own subcommands are told to run by their options:
/// `rebase -x CMD` (`--exec`), `bisect run CMD ARGS…`, `grep
/// -O[CMD]` (`--open-files-in-pager`), `difftool -x CMD` (`--extcmd`),
/// `clone -u CMD`, `fetch`, `pull`, `ls-remote` and `archive`'s
/// `--upload-pack` (also `--exec`), `push`'s and `send-pack`'s
/// `--receive-pack` (also `--exec`), and `send-email`'s `--sendmail-cmd`
/// `--to-cmd`, `--cc-cmd` and `--header-cmd`, and a `--smtp-server` that is
/// a program's path. git runs each through a
/// shell; a long option may be any prefix of its name.
fn git_options(args: &[Arg]) -> Vec<Arg> {
    let global = git_global(args);
    let Some(sub) = args.get(global.at).and_then(Arg::known) else {
        return Vec::new();
    };
    let rest = args.get(global.at + 1..).unwrap_or_default();
    let long = |names: &'static [&'static str]| {
        move |text: &str| names.iter().any(|name| git_long(text, name))
    };
    match sub {
        "rebase" => values_of(
            rest,
            Some('x'),
            long(&["exec"]),
            "sX",
            &["onto", "strategy", "strategy-option"],
        ),
        "difftool" => values_of(
            rest,
            Some('x'),
            long(&["extcmd"]),
            "t",
            &["tool", "rotate-to", "skip-to"],
        ),
        "grep" => {
            // `-O` and `--open-files-in-pager` take their command only
            // joined to them; alone they run the pager.
            rest.iter()
                .filter_map(Arg::known)
                .take_while(|text| *text != "--")
                .filter_map(|text| {
                    text.strip_prefix("-O")
                        .filter(|command| !command.is_empty())
                        .or_else(|| {
                            text.split_once('=')
                                .filter(|(name, _)| git_long(name, "open-files-in-pager"))
                                .map(|(_, command)| command)
                        })
                })
                .map(|command| Arg::Known(command.to_string()))
                .collect()
        }
        "clone" => values_of(
            rest,
            Some('u'),
            long(&["upload-pack"]),
            "obcj",
            &["origin", "branch", "config", "jobs", "reference", "depth"],
        ),
        "fetch" | "pull" | "ls-remote" | "archive" => values_of(
            rest,
            None,
            long(&["upload-pack", "exec"]),
            "j",
            &["jobs", "depth", "remote", "format", "prefix", "output"],
        ),
        "push" | "send-pack" => {
            values_of(rest, None, long(&["receive-pack", "exec"]), "o", &["repo"])
        }
        "send-email" => {
            let mut commands = values_of(
                rest,
                None,
                long(&["sendmail-cmd", "to-cmd", "cc-cmd", "header-cmd"]),
                "",
                &[],
            );
            commands.extend(
                values_of(rest, None, long(&["smtp-server"]), "", &[])
                    .into_iter()
                    .filter(|server| server.known().is_none_or(|text| text.starts_with('/')))
                    .map(|server| read_value(&server, Value::Program)),
            );
            commands
        }
        "bisect" => bisect_run(rest).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// The command `git bisect run CMD ARGS…` runs at each step: the first word
/// as written, a shell line, and the others handed to it as words, as git
/// runs it (`sh -c 'CMD "$@"' CMD ARGS…`), so each is read quoted.
fn bisect_run(rest: &[Arg]) -> Option<Arg> {
    let (first, words) = match rest {
        [run, first, words @ ..] if run.known() == Some("run") => (first, words),
        _ => return None,
    };
    let mut line = first.text().to_string();
    for word in words {
        line.push(' ');
        match word.known() {
            Some(text) => {
                line.push('\'');
                line.push_str(&text.replace('\'', r"'\''"));
                line.push('\'');
            }
            None => line.push_str(word.text()),
        }
    }
    Some(
        if first.known().is_some() && words.iter().all(|word| word.known().is_some()) {
            Arg::Known(line)
        } else {
            Arg::Unknown(line)
        },
    )
}

/// The `-o` settings of OpenSSH's programs that name a command it runs
/// here, through the user's shell: `ProxyCommand`, `LocalCommand` and
/// `KnownHostsCommand`, the name in any case and its value after `=` or
/// white space (`none` runs nothing). And the program `scp -S` and `sftp
/// -S` connect with, and the command `sftp -D` runs as its server. Every
/// word is read, after the host too: OpenSSH reads its options there as
/// well.
fn ssh_options(key: &str, args: &[Arg]) -> Vec<Arg> {
    let valued = match key {
        "scp" => "cDFiJloPSX",
        "sftp" => "BbcDFiJloPRsSX",
        "autossh" => "BbcDEeFIiJLlmMOoPpQRSWw",
        "ssh-copy-id" => "iopFt",
        _ => "BbcDEeFIiJLlmOoPpQRSWw",
    };
    let mut commands: Vec<Arg> = values_of(args, Some('o'), |_| false, valued, &[])
        .iter()
        .filter_map(|setting| {
            if let Some(text) = setting.known() {
                return ssh_setting(text).map(|command| Arg::Known(command.to_string()));
            }
            // A setting only known when it runs is a command only known when
            // it runs, unless its key is written out and is none of them.
            let text = match setting {
                Arg::Template { text, .. } => text.as_str(),
                other => other.text(),
            };
            let text = text.trim_start_matches(['"', '\'']).trim_start();
            let key = text
                .split(|c: char| c == '=' || c.is_whitespace())
                .next()
                .unwrap_or_default();
            let written = !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric());
            (!written || ssh_setting(&format!("{key}=x")).is_some()).then(|| setting.clone())
        })
        .collect();
    if matches!(key, "scp" | "sftp") {
        commands.extend(
            values_of(args, Some('S'), |_| false, valued, &[])
                .iter()
                .map(|program| read_value(program, Value::Program)),
        );
    }
    if key == "sftp" {
        commands.extend(values_of(args, Some('D'), |_| false, valued, &[]));
    }
    commands
}

/// The libraries OpenSSH's programs are told to load, native code the guard
/// does not read: `ssh -I LIB` (a PKCS#11 provider), and the
/// `PKCS11Provider` and `SecurityKeyProvider` settings of `-o` (the key in
/// any case; `none` loads none). A setting only known when it runs may be
/// one.
fn ssh_libraries(key: &str, args: &[Arg]) -> Vec<Arg> {
    let valued = if key == "ssh" || key == "slogin" || key == "autossh" {
        "BbcDEeFIiJLlmMOoPpQRSWw"
    } else {
        "cDFiJloPSX"
    };
    let mut found = Vec::new();
    if key == "ssh" || key == "slogin" || key == "autossh" {
        found.extend(values_of(args, Some('I'), |_| false, valued, &[]));
    }
    for setting in values_of(args, Some('o'), |_| false, valued, &[]) {
        let Some(text) = setting.known() else {
            continue;
        };
        let text = text.trim_start();
        let end = text
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(text.len());
        let (name, rest) = text.split_at(end);
        let value = rest.trim_start();
        let value = value.strip_prefix('=').unwrap_or(value).trim_start();
        let loads = ["PKCS11Provider", "SecurityKeyProvider"]
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name));
        if loads && !value.is_empty() && !value.eq_ignore_ascii_case("none") {
            found.push(Arg::Known(value.to_string()));
        }
    }
    found
}

/// The commands `sshfs -o` names in its comma-separated options:
/// `ssh_command=CMD`, which it runs in place of ssh, and the ssh settings
/// it hands on (`ProxyCommand=CMD`).
fn sshfs_options(args: &[Arg]) -> Vec<Arg> {
    let mut commands = Vec::new();
    for options in values_of(args, Some('o'), |_| false, "pF", &[]) {
        let Some(text) = options.known() else {
            commands.push(options.clone());
            continue;
        };
        for option in text.split(',') {
            if let Some(command) = option.trim().strip_prefix("ssh_command=") {
                commands.push(Arg::Known(command.to_string()));
            } else if let Some(command) = ssh_setting(option) {
                commands.push(Arg::Known(command.to_string()));
            }
        }
    }
    commands
}

/// The command an ssh setting `KEY=VALUE` (or `KEY VALUE`) runs, when its
/// key is one that names a command.
fn ssh_setting(text: &str) -> Option<&str> {
    let text = text.trim_start();
    let end = text
        .find(|c: char| c == '=' || c.is_whitespace())
        .unwrap_or(text.len());
    let (name, rest) = text.split_at(end);
    let value = rest.trim_start();
    let value = value.strip_prefix('=').unwrap_or(value).trim_start();
    let runs = ["ProxyCommand", "LocalCommand", "KnownHostsCommand"]
        .iter()
        .any(|key| key.eq_ignore_ascii_case(name));
    (runs && !value.is_empty() && !value.eq_ignore_ascii_case("none")).then_some(value)
}

/// The program GNU `sort --compress-program=PROG` compresses its temporary
/// files with, also given as any prefix of the name that no other option
/// starts (`--co`), and with its value as the next word.
fn sort_options(args: &[Arg]) -> Vec<Arg> {
    values_of(
        args,
        None,
        |text| {
            text.strip_prefix("--")
                .is_some_and(|name| name.len() > 1 && "compress-program".starts_with(name))
        },
        "kotST",
        &[
            "key",
            "output",
            "field-separator",
            "buffer-size",
            "temporary-directory",
            "parallel",
            "batch-size",
            "files0-from",
            "sort",
            "random-source",
        ],
    )
    .iter()
    .map(|program| read_value(program, Value::Program))
    .collect()
}

/// The shell commands `less` is given to run when it starts: `+!CMD`
/// (also `++!CMD`, and after other commands, `+G!CMD`), and `+|mCMD`, which
/// pipes to `CMD`.
fn less_options(args: &[Arg]) -> Vec<Arg> {
    let mut commands = Vec::new();
    for arg in args {
        let Some(text) = arg.known() else {
            if arg.text().starts_with('+') {
                commands.push(arg.clone());
            }
            continue;
        };
        if text == "--" {
            break;
        }
        let Some(command) = text.strip_prefix('+') else {
            continue;
        };
        let command = command.trim_start_matches('+');
        // `+G!cmd`: the commands before a `!` run first, then the shell.
        if let Some((_, line)) = command.split_once('!') {
            commands.push(Arg::Known(line.to_string()));
        } else if let Some(marked) = command.strip_prefix('|') {
            let mut chars = marked.chars();
            chars.next();
            commands.push(Arg::Known(chars.as_str().to_string()));
        }
    }
    commands
}

/// What `fd` (Debian's `fdfind`) does: it reads, and with `-x CMD…`
/// (`--exec`) it runs the command for each path it finds, with `-X CMD…`
/// (`--exec-batch`) once with them all. The command is the words after the
/// option up to a `;`, fd starts it itself with no shell, and each
/// placeholder in it (`{}`, `{/}`, `{//}`, `{.}`, `{/.}`) is a path only known
/// when it runs, put after the words when none is written. Both are judged:
/// fd itself, and the command.
pub(super) fn fd(unit: &Unit, key: &str) -> Launch {
    let args = &unit.args;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let first = match text {
            "--exec" | "--exec-batch" => None,
            _ => match text
                .strip_prefix("--exec=")
                .or_else(|| text.strip_prefix("--exec-batch="))
            {
                Some(first) => Some(Arg::Known(first.to_string())),
                None => match fd_bundle(text) {
                    Some(attached) => {
                        (!attached.is_empty()).then(|| Arg::Known(attached.to_string()))
                    }
                    None => continue,
                },
            },
        };
        let end = args[at..]
            .iter()
            .position(|word| word.known() == Some(";"))
            .map_or(args.len(), |end| at + end);
        let mut words: Vec<Arg> = first
            .into_iter()
            .chain(args[at..end].iter().cloned())
            .collect();
        if words.is_empty() {
            return Launch::Itself;
        }
        let mut placed = false;
        for word in &mut words {
            if word
                .known()
                .is_some_and(|text| PLACEHOLDERS.contains(&text))
            {
                placed = true;
                *word = Arg::Unknown(word.text().to_string());
            }
        }
        if !placed {
            words.push(Arg::Unknown("{}".to_string()));
        }
        let mut run = super::wrappers::running(unit, key, 0);
        let mut words = words.into_iter();
        run.program = words.next().unwrap_or(Arg::Unknown(String::new()));
        run.args = words.collect();
        return Launch::Either(
            Box::new(Launch::Itself),
            Box::new(Launch::Replace(Box::new(run))),
        );
    }
    Launch::Itself
}

/// What a bundle of fd's short options (`-Hx`, `-HIxrm`, `-X=rm`) says
/// of `-x` or `-X`, read as clap reads one: `None` when it holds neither
/// before a letter that takes a value of its own (`-dx` gives `-d` the value
/// `x`); otherwise the command's first word when it is attached, after an
/// optional `=`, and an empty text when none is.
fn fd_bundle(text: &str) -> Option<&str> {
    /// fd's short options that take a value.
    const VALUED: &str = "dteEcjSoC";
    let bundle = text
        .strip_prefix('-')
        .filter(|rest| !rest.starts_with('-'))?;
    for (at, letter) in bundle.char_indices() {
        if letter == 'x' || letter == 'X' {
            let rest = &bundle[at + 1..];
            let rest = rest.strip_prefix('=').unwrap_or(rest);
            return Some(rest);
        }
        if VALUED.contains(letter) {
            return None;
        }
    }
    None
}

/// The placeholders of `fd -x` for the path it found.
const PLACEHOLDERS: [&str; 5] = ["{}", "{/}", "{//}", "{.}", "{/.}"];

/// The programs `rg` runs: `--pre PROG`, the preprocessor it hands each
/// file to, and `--hostname-bin PROG`, which prints the host's name.
fn rg_options(args: &[Arg]) -> Vec<Arg> {
    values_of(
        args,
        None,
        |text| matches!(text, "--pre" | "--hostname-bin"),
        "ABCdEefgjMmrtT",
        &[
            "after-context",
            "before-context",
            "context",
            "encoding",
            "regexp",
            "file",
            "glob",
            "iglob",
            "threads",
            "max-columns",
            "max-count",
            "replace",
            "type",
            "type-not",
            "pre-glob",
            "type-add",
            "type-clear",
            "sort",
            "sortr",
            "colors",
            "color",
            "path-separator",
            "max-depth",
            "max-filesize",
            "ignore-file",
            "field-match-separator",
            "field-context-separator",
            "context-separator",
            "dfa-size-limit",
            "regex-size-limit",
            "engine",
            "hyperlink-format",
        ],
    )
    .iter()
    .map(|program| read_value(program, Value::Program))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &[&str]) -> Vec<Arg> {
        text.iter()
            .map(|word| Arg::Known((*word).to_string()))
            .collect()
    }

    #[test]
    fn an_ssh_setting_names_a_command_by_its_key_in_any_case() {
        assert_eq!(ssh_setting("ProxyCommand=nc %h %p"), Some("nc %h %p"));
        assert_eq!(ssh_setting("proxycommand nc %h %p"), Some("nc %h %p"));
        assert_eq!(ssh_setting("LocalCommand = x"), Some("x"));
        assert_eq!(ssh_setting("KnownHostsCommand=x"), Some("x"));
        assert_eq!(ssh_setting("ProxyCommand=none"), None);
        assert_eq!(ssh_setting("ProxyCommand="), None);
        assert_eq!(ssh_setting("ProxyJump=jump"), None);
    }

    #[test]
    fn values_are_read_where_getopt_reads_them() {
        let found = values_of(
            &words(&["-ix", "a", "-xb", "--", "-x", "c"]),
            Some('x'),
            |_| false,
            "",
            &[],
        );
        assert_eq!(found, words(&["a", "b"]));
        let found = values_of(
            &words(&["-o", "-x", "-x", "a"]),
            Some('x'),
            |_| false,
            "o",
            &[],
        );
        assert_eq!(found, words(&["a"]));
        let found = values_of(
            &words(&["--ex=a", "--exec", "b", "--onto", "--exec"]),
            None,
            |text| git_long(text, "exec"),
            "",
            &["onto"],
        );
        assert_eq!(found, words(&["a", "b"]));
    }

    #[test]
    fn a_preprocessor_is_read_after_its_marks() {
        let line = |text: &str| read_value(&Arg::Known(text.to_string()), Value::Preprocessor);
        assert_eq!(line("|lesspipe %s"), Arg::Known("lesspipe %s".to_string()));
        assert_eq!(line("||-x %s"), Arg::Known("x %s".to_string()));
        assert_eq!(line("lesspipe %s"), Arg::Known("lesspipe %s".to_string()));
    }

    #[test]
    fn a_variable_is_named_in_any_case_on_windows() {
        assert_eq!(command_variable("git_ssh_command"), Some("GIT_SSH_COMMAND"));
        assert!(is_command_variable("PAGER"));
        assert!(!is_command_variable("pager"));
        assert_eq!(command_variable("PATH"), None);
    }
}
