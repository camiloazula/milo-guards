//! Programs that start the command after their own options: Windows'
//! console hosts and remote runners (`conhost`, `wt`, `psexec`, `nircmd`,
//! `pcalua`, `rundll32`'s launchers, `gsudo`), and on POSIX systems the
//! queues, session and display runners, the programs that run a command as
//! another user, in other limits or in a toolbox, and the terminal
//! emulators. Each reads the command after its own options; where an
//! option is one the guard does not know, the option may take the word
//! after it, so where the command starts is not read (`unreadable`).

use super::tools::{after_known, UNKNOWN_OPTION, UNKNOWN_WORD};
use super::wrappers::{folder_option, in_folder, running};
use super::{after_getopt, getopt_value, getopt_word, join, mapped, runs, Launch, Word};
use crate::located::Source;
use crate::unit::{Arg, Unit};
use crate::Shell;

/// A launcher's options: those that take the next word as their value (or
/// their value after `=`), and those that take none. A short one may stand
/// in a bundle (`-ab`), where one that takes a value takes the rest of the
/// word, or the next word at its end.
struct Table {
    values: &'static [&'static str],
    flags: &'static [&'static str],
}

impl Table {
    /// How many words the option `text` takes, itself among them; `None` for
    /// one the table does not name.
    fn read(&self, text: &str) -> Option<usize> {
        if self.values.contains(&text) {
            return Some(2);
        }
        if self.flags.contains(&text) {
            return Some(1);
        }
        if let Some((name, _)) = text.split_once('=') {
            if name.starts_with("--") && self.values.contains(&name) {
                return Some(1);
            }
        }
        let bundle = text
            .strip_prefix('-')
            .filter(|rest| !rest.starts_with('-'))?;
        for (at, letter) in bundle.char_indices() {
            let short = format!("-{letter}");
            if self.values.contains(&short.as_str()) {
                return Some(if at + letter.len_utf8() == bundle.len() {
                    2
                } else {
                    1
                });
            }
            if !self.flags.contains(&short.as_str()) {
                return None;
            }
        }
        Some(1)
    }

    /// What a launcher that runs the program after these options, from the
    /// word at `from`, runs: the program, or a command that is not read past
    /// an option the table does not name.
    fn after(&self, args: &[Arg], from: usize) -> Launch {
        match after_known(args, from, |text| self.read(text)) {
            Ok(at) => runs(args, Some(at)),
            Err(_) => Launch::Opaque(UNKNOWN_OPTION),
        }
    }
}

/// `conhost [OPTIONS] [--] COMMAND…`, the console host: it runs the command
/// line after its options in a console of its own. Its options compare
/// without case; a handle it is given first (`0x4`) is one of them.
pub(super) fn conhost(args: &[Arg]) -> Launch {
    const VALUES: &[&str] = &[
        "--server",
        "--signal",
        "--width",
        "--height",
        "--feature",
        "--vtmode",
        "--textmeasurement",
    ];
    const FLAGS: &[&str] = &[
        "--headless",
        "--inheritcursor",
        "--resizequirk",
        "--forcev1",
        "-forcev1",
        "--win32input",
    ];
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        // A word only known when it runs is the program, as for `sudo`.
        let Some(text) = arg.known().map(str::to_ascii_lowercase) else {
            return runs(args, Some(at));
        };
        match text.as_str() {
            "--" => return runs(args, Some(at + 1)),
            text if VALUES.contains(&text) => at += 2,
            text if FLAGS.contains(&text) || text.starts_with("0x") => at += 1,
            text if text.starts_with('-') => return Launch::Opaque(UNKNOWN_OPTION),
            _ => return runs(args, Some(at)),
        }
    }
    Launch::Itself
}

/// Windows Terminal, `wt [OPTIONS] [SUBCOMMAND [OPTIONS] [COMMAND…]] [; …]`:
/// each `new-tab` (`nt`) and `split-pane` (`sp`), and the commands written
/// with neither (a new tab), runs the command line after its options, in
/// the folder `-d` (`--startingDirectory`) names; the commands are set
/// apart by a `;` word. The subcommands that only move the focus or a pane
/// run nothing. Every command is judged, so the riskiest counts.
pub(super) fn wt(unit: &Unit) -> Launch {
    const GLOBAL: Table = Table {
        values: &["-w", "--window", "--pos", "--size"],
        flags: &["-M", "--maximized", "-F", "--fullscreen", "-f", "--focus"],
    };
    const PANE: Table = Table {
        values: &[
            "-p",
            "--profile",
            "-d",
            "--startingDirectory",
            "--title",
            "--tabColor",
            "--colorScheme",
            "-s",
            "--size",
        ],
        flags: &[
            "--suppressApplicationTitle",
            "--useApplicationTitle",
            "-H",
            "--horizontal",
            "-V",
            "--vertical",
            "-D",
            "--duplicate",
            "--inheritEnvironment",
        ],
    };
    const RUNS: [&str; 4] = ["new-tab", "nt", "split-pane", "sp"];
    const MOVES: [&str; 9] = [
        "focus-tab",
        "ft",
        "move-focus",
        "mf",
        "move-pane",
        "mp",
        "swap-pane",
        "focus-pane",
        "fp",
    ];
    let args = &unit.args;
    let mut readings = Vec::new();
    let mut start = 0;
    let mut first = true;
    while start <= args.len() {
        let end = args[start..]
            .iter()
            .position(|arg| arg.known() == Some(";"))
            .map_or(args.len(), |at| start + at);
        let segment = &args[start..end];
        let mut at = 0;
        if first {
            match after_known(segment, 0, |text| {
                GLOBAL.read(text).or_else(|| PANE.read(text))
            }) {
                Ok(next) => at = next,
                Err(_) => return Launch::Opaque(UNKNOWN_OPTION),
            }
        }
        first = false;
        let sub = segment.get(at).and_then(Arg::known);
        if sub.is_some_and(|sub| MOVES.contains(&sub)) {
            start = end + 1;
            continue;
        }
        if sub.is_some_and(|sub| RUNS.contains(&sub)) {
            at += 1;
        }
        let Ok(program) = after_known(segment, at, |text| PANE.read(text)) else {
            return Launch::Opaque(UNKNOWN_OPTION);
        };
        if program < segment.len() {
            let mut run = running(unit, "wt", start + program);
            run.args.truncate(end - start - program - 1);
            let own = &segment[..program];
            let folder = folder_option(own, &["-d", "--startingDirectory"], false, |text, _| {
                if PANE.read(text) == Some(2) {
                    Word::Value
                } else {
                    Word::Flag
                }
            });
            readings.push(in_folder(folder, Launch::Replace(Box::new(run))));
            // Each command is one more reading: past the forks a line may make
            // it is unreadable whatever follows, so no more are built.
            if readings.len() > super::MAX_FORKS {
                return Launch::Opaque("reads in too many ways to judge each");
            }
        }
        start = end + 1;
    }
    readings
        .into_iter()
        .reduce(|first, second| Launch::Either(Box::new(first), Box::new(second)))
        .unwrap_or(Launch::Itself)
}

/// `psexec [\\COMPUTER | @FILE] [OPTIONS] PROGRAM [ARGS…]` (Sysinternals'
/// `PsExec`, `PsExec64`, and `PAExec`, which reads the same options and some
/// more): it runs the program, here or on the computer it names, through a
/// service it installs, so as an administrator. Its options start with `-`
/// or `/` and compare without case; `-w DIR` starts the program in `DIR`,
/// and `-i` takes a session only when a number follows it.
pub(super) fn psexec(args: &[Arg]) -> Launch {
    const VALUES: &[&str] = &[
        "u", "p", "n", "r", "w", "a", "lo", "rlo", "to", "csrc", "clist", "share", "sname",
    ];
    const FLAGS: &[&str] = &[
        "h",
        "l",
        "s",
        "e",
        "x",
        "d",
        "c",
        "f",
        "v",
        "accepteula",
        "nobanner",
        "low",
        "belownormal",
        "abovenormal",
        "high",
        "realtime",
        "background",
        "dbg",
        "noname",
        "cnodel",
        "dfr",
    ];
    let mut at = 0;
    if args
        .first()
        .and_then(Arg::known)
        .is_some_and(|first| first.starts_with("\\\\") || first.starts_with('@'))
    {
        at = 1;
    }
    let mut folder = None;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            return in_folder(folder, runs(args, Some(at)));
        };
        // The computers may stand after the options too (`psexec -s
        // \\server cmd`).
        if text.starts_with("\\\\") || text.starts_with('@') {
            at += 1;
            continue;
        }
        let Some(option) = text
            .strip_prefix('-')
            .or_else(|| text.strip_prefix('/'))
            .filter(|option| !option.is_empty())
        else {
            return in_folder(folder, runs(args, Some(at)));
        };
        let option = option.to_ascii_lowercase();
        if option == "w" {
            folder = args.get(at + 1).cloned();
        }
        at += if VALUES.contains(&option.as_str()) {
            2
        } else if option == "i" {
            let session = args
                .get(at + 1)
                .and_then(Arg::known)
                .is_some_and(|next| !next.is_empty() && next.bytes().all(|b| b.is_ascii_digit()));
            1 + usize::from(session)
        } else if FLAGS.contains(&option.as_str()) {
            1
        } else {
            return Launch::Opaque(UNKNOWN_OPTION);
        };
    }
    Launch::Itself
}

/// `gsudo [OPTIONS] COMMAND…`: it runs the command as an administrator.
/// Its options compare without case; `-i` (`--integrity`), `-u` (`--user`),
/// and `--loglevel` take a value.
pub(super) fn gsudo(args: &[Arg]) -> Launch {
    const VALUES: &[&str] = &["-i", "--integrity", "-u", "--user", "--loglevel"];
    const FLAGS: &[&str] = &[
        "-n",
        "--new",
        "-w",
        "--wait",
        "--keepshell",
        "--keepwindow",
        "--close",
        "-d",
        "--direct",
        "--loadprofile",
        "-s",
        "--system",
        "--ti",
        "-k",
        "--copyns",
        "--copyev",
        "--debug",
    ];
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known().map(str::to_ascii_lowercase) else {
            return runs(args, Some(at));
        };
        match text.as_str() {
            "--" => return runs(args, Some(at + 1)),
            text if VALUES.contains(&text) => at += 2,
            text if FLAGS.contains(&text) => at += 1,
            text if text.len() > 1 && text.starts_with('-') => {
                return Launch::Opaque(UNKNOWN_OPTION)
            }
            _ => return runs(args, Some(at)),
        }
    }
    Launch::Itself
}

/// `nircmd` (also `nircmdc`), the command runner of `NirSoft`: `exec SHOW PROGRAM
/// ARGS…`, `exec2 SHOW FOLDER PROGRAM ARGS…` (started in `FOLDER`),
/// `elevate PROGRAM ARGS…` and `runassystem PROGRAM ARGS…` run a program;
/// `execmd COMMAND…` runs a line of cmd; `elevatecmd COMMAND…` and
/// `cmdwait MS COMMAND…` run one of its own commands. Its others run none.
pub(super) fn nircmd(unit: &Unit, key: &str) -> Launch {
    let args = &unit.args;
    let Some(command) = args
        .first()
        .and_then(Arg::known)
        .map(str::to_ascii_lowercase)
    else {
        return match args.first() {
            Some(_) => Launch::Opaque(UNKNOWN_WORD),
            None => Launch::Itself,
        };
    };
    let again = |at: usize| {
        if at < args.len() {
            let mut run = running(unit, key, at - 1);
            run.program = Arg::Known(key.to_string());
            Launch::Replace(Box::new(run))
        } else {
            Launch::Itself
        }
    };
    match command.as_str() {
        "exec" => runs(args, Some(2)),
        "exec2" => in_folder(args.get(2).cloned(), runs(args, Some(3))),
        "elevate" | "runassystem" => runs(args, Some(1)),
        "execmd" if args.len() > 1 => {
            Launch::Script(Shell::Cmd, join(&args[1..]), Source::joined(&args[1..]))
        }
        "elevatecmd" => again(1),
        "cmdwait" => again(2),
        _ => Launch::Itself,
    }
}

/// `pcalua -a PROGRAM [-c ARGS] [-d FOLDER]`, the Program Compatibility
/// Assistant: it starts the program with the command line `-c` gives, in
/// the folder `-d` names. The program and its arguments are one command
/// line, read as cmd reads one. A library it is given (`-a x.dll`) is
/// native code, `unknown` (`detect`).
pub(super) fn pcalua(args: &[Arg]) -> Launch {
    let value = |name: &str| {
        args.iter()
            .position(|arg| {
                arg.known()
                    .is_some_and(|text| text.eq_ignore_ascii_case(name))
            })
            .and_then(|at| args.get(at + 1))
    };
    let Some(program) = value("-a") else {
        return Launch::Itself;
    };
    // The command line `-c` gives runs to the next option of pcalua's own,
    // quoted or not (`-c /c rd /s /q C:\x`).
    let own = |arg: &Arg| {
        arg.known().is_some_and(|text| {
            ["-a", "-c", "-d", "-m", "-p"]
                .iter()
                .any(|name| text.eq_ignore_ascii_case(name))
        })
    };
    let arguments: Vec<Arg> = args
        .iter()
        .position(|arg| {
            arg.known()
                .is_some_and(|text| text.eq_ignore_ascii_case("-c"))
        })
        .map(|at| {
            args[at + 1..]
                .iter()
                .take_while(|arg| !own(arg))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let line: Vec<Arg> = std::iter::once(program.clone()).chain(arguments).collect();
    in_folder(
        value("-d").cloned(),
        Launch::Script(Shell::Cmd, join(&line), Source::NONE),
    )
}

/// `rundll32 LIBRARY,FUNCTION ARGS…` where the function starts the program
/// its arguments name: shell32's `ShellExec_RunDLL` (and its `A` and `W`),
/// url's `FileProtocolHandler` and zipfldr's `RouteTheCall`. Any other
/// function is the program itself.
pub(super) fn rundll32(args: &[Arg]) -> Launch {
    let Some(first) = args.first().and_then(Arg::known) else {
        return Launch::Itself;
    };
    let lower = first.to_ascii_lowercase();
    let (library, mut function, mut at) = match lower.split_once(',') {
        Some((library, function)) => (library.to_string(), function.trim().to_string(), 1),
        None => (lower.clone(), String::new(), 1),
    };
    if function.is_empty() {
        function = args
            .get(1)
            .and_then(Arg::known)
            .map(|text| text.trim_start_matches(',').trim().to_ascii_lowercase())
            .unwrap_or_default();
        at = 2;
    }
    let library = library.rsplit(['\\', '/']).next().unwrap_or(&library);
    let library = library.strip_suffix(".dll").unwrap_or(library);
    let launches = matches!(
        (library, function.as_str()),
        (
            "shell32",
            "shellexec_rundll" | "shellexec_rundlla" | "shellexec_rundllw"
        ) | ("url", "fileprotocolhandler")
            | ("zipfldr", "routethecall")
    );
    if launches {
        runs(args, Some(at))
    } else {
        Launch::Itself
    }
}

/// `mshta`, the HTML application host: given a file (`app.hta`, a path on
/// this machine's disk) it runs the workspace's own application, as a
/// script file is. Any other target is code the line does not show: one on
/// another machine (`http:`, `https:`, `ftp:`, a share, `\\server\x.hta`) a
/// script it downloads, and any other scheme (`vbscript:`, `javascript:`,
/// `about:` with a script in it, `file:`, `res:`, `mhtml:`) code the guard
/// does not read.
pub(super) fn mshta(args: &[Arg]) -> Launch {
    let Some(first) = args.first() else {
        return Launch::Itself;
    };
    let Some(text) = first.known() else {
        return Launch::Unread(first.clone());
    };
    let target = text.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
    let lower = target.to_ascii_lowercase();
    let remote = ["http:", "https:", "ftp:"]
        .iter()
        .any(|scheme| lower.starts_with(scheme))
        || lower.starts_with("\\\\")
        || lower.starts_with("//")
        || lower.starts_with("file://")
            && !lower.starts_with("file:///")
            && !lower["file://".len()..].starts_with("localhost/");
    let scheme = lower.split_once(':').is_some_and(|(name, _)| {
        name.len() > 1
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    });
    if remote {
        Launch::Downloaded
    } else if scheme || target.is_empty() {
        Launch::Reads(crate::unit::Reads::Interpreter)
    } else {
        Launch::Itself
    }
}

/// task-spooler's `tsp [OPTIONS] COMMAND…`: it queues the command, which it
/// runs later. `-L`, `-D`, `-W` and `-N` take a value; an option that acts
/// on the queue (`-l`, `-t`, `-k`, …) runs no command.
pub(super) fn tsp(args: &[Arg]) -> Launch {
    const ACTS: &str = "KClStcpoisrwkTuUhV";
    const TABLE: Table = Table {
        values: &["-L", "-D", "-W", "-N"],
        flags: &["-n", "-E", "-g", "-f", "-m", "-d", "-B", "-z"],
    };
    queued(args, ACTS, &TABLE)
}

/// What a queue of commands runs: the command after its options (`table`),
/// or none when one of them acts on the queue (a letter of `acts`).
fn queued(args: &[Arg], acts: &str, table: &Table) -> Launch {
    let acting = |text: &str| {
        let mut letters = text.chars().skip(1);
        text.len() == 2 && letters.next().is_some_and(|letter| acts.contains(letter))
    };
    let options = args.iter().take_while(|arg| {
        arg.known()
            .is_some_and(|text| text.len() > 1 && text.starts_with('-') && text != "--")
    });
    if options.filter_map(Arg::known).any(acting) {
        return Launch::Itself;
    }
    table.after(args, 0)
}

/// `nq [-c] [-q] COMMAND…` queues the command; `-t` and `-w` run none.
pub(super) fn nq(args: &[Arg]) -> Launch {
    const TABLE: Table = Table {
        values: &[],
        flags: &["-c", "-q"],
    };
    queued(args, "tw", &TABLE)
}

/// `dbus-launch [OPTIONS] PROGRAM…` starts a session bus and the program.
pub(super) fn dbus_launch(args: &[Arg]) -> Launch {
    Table {
        values: &["--autolaunch", "--config-file"],
        flags: &[
            "--sh-syntax",
            "--csh-syntax",
            "--auto-syntax",
            "--binary-syntax",
            "--close-stderr",
            "--exit-with-session",
            "--exit-with-x11",
            "--version",
            "--help",
        ],
    }
    .after(args, 0)
}

/// `dbus-run-session [OPTIONS] [--] PROGRAM…` runs the program on a session
/// bus of its own.
pub(super) fn dbus_run_session(args: &[Arg]) -> Launch {
    Table {
        values: &["--config-file", "--dbus-daemon"],
        flags: &["--help", "--version"],
    }
    .after(args, 0)
}

/// `xvfb-run [OPTIONS] COMMAND…` runs the command on a virtual display; its
/// options are read as `getopt` reads them, up to the command.
pub(super) fn xvfb_run(args: &[Arg]) -> Launch {
    runs(
        args,
        after_getopt(
            args,
            "efnpsw",
            &[
                "error-file",
                "auth-file",
                "server-num",
                "xauth-protocol",
                "server-args",
                "wait",
            ],
        ),
    )
}

/// util-linux's `runuser`: `-c CMD` (`--command`, wherever it stands, as
/// getopt finds it) runs a shell line as the user; with `-u USER` the
/// command after the options runs as that user, with no shell.
pub(super) fn runuser(args: &[Arg]) -> Launch {
    const TABLE: Table = Table {
        values: &[
            "-u",
            "--user",
            "-g",
            "--group",
            "-G",
            "--supp-group",
            "-s",
            "--shell",
            "-w",
            "--whitelist-environment",
        ],
        flags: &[
            "-",
            "-l",
            "--login",
            "-m",
            "-p",
            "--preserve-environment",
            "-P",
            "--pty",
            "-f",
            "--fast",
        ],
    };
    if let Some(script) = getopt_value(
        args,
        Some('c'),
        "command",
        "ugGsw",
        &[
            "user",
            "group",
            "supp-group",
            "shell",
            "whitelist-environment",
        ],
    ) {
        return Launch::Script(Shell::Posix, script, Source::NONE);
    }
    // After `--` the words are the user and what is handed to the shell,
    // which runs the line after a `-c` there (`runuser -- root -c CMD`,
    // `runuser root -- -c CMD`).
    if let Some(dash) = args.iter().position(|arg| arg.known() == Some("--")) {
        let after = &args[dash + 1..];
        if let Some(at) = after
            .iter()
            .position(|arg| matches!(arg.known(), Some("-c" | "--command")))
        {
            if let Some(script) = after.get(at + 1) {
                return Launch::Script(Shell::Posix, script.clone(), Source::arg(script));
            }
        }
    }
    let user = args
        .iter()
        .filter_map(Arg::known)
        .take_while(|text| *text != "--")
        .any(|text| text == "-u" || text.starts_with("--user") || text.starts_with("-u"));
    if user {
        TABLE.after(args, 0)
    } else {
        Launch::Itself
    }
}

/// `sg [-] GROUP [-c] COMMAND`: it runs the command, a shell line, with the
/// group. Words a shell reads back as they are (no white space, quote,
/// expansion, operator or pattern in them) make the same words when joined
/// and read again, so they are read as the program and its arguments, which
/// costs no second reading of the rest of the line at every `sg` of a chain
/// of them; any other word makes the line the shell reads.
pub(super) fn sg(args: &[Arg]) -> Launch {
    let mut at = usize::from(args.first().and_then(Arg::known) == Some("-")) + 1;
    if args.get(at).and_then(Arg::known) == Some("-c") {
        at += 1;
    }
    let plain = |arg: &Arg| {
        arg.known().is_some_and(|text| {
            !text.is_empty()
                && !text.contains(|c: char| {
                    c.is_whitespace() || "'\"\\$`;&|<>()*?[]{}~#!=%".contains(c)
                })
        })
    };
    match args.get(at..) {
        Some(rest) if !rest.is_empty() && rest.iter().all(plain) => runs(args, Some(at)),
        Some(rest) if !rest.is_empty() => {
            Launch::Script(Shell::Posix, join(rest), Source::joined(rest))
        }
        _ => Launch::Itself,
    }
}

/// util-linux's `setpriv [OPTIONS] PROGRAM…`: it runs the program with the
/// user, groups and privileges its options give.
pub(super) fn setpriv(args: &[Arg]) -> Launch {
    Table {
        values: &[
            "--ruid",
            "--euid",
            "--reuid",
            "--rgid",
            "--egid",
            "--regid",
            "--groups",
            "--inh-caps",
            "--ambient-caps",
            "--bounding-set",
            "--securebits",
            "--pdeathsig",
            "--selinux-label",
            "--apparmor-profile",
            "--landlock-access",
            "--landlock-rule",
            "--seccomp-filter",
        ],
        flags: &[
            "-d",
            "--dump",
            "--nnp",
            "--no-new-privs",
            "--keep-groups",
            "--clear-groups",
            "--init-groups",
            "--reset-env",
            "--list-caps",
            "-h",
            "--help",
            "-V",
            "--version",
        ],
    }
    .after(args, 0)
}

/// `numactl [OPTIONS] PROGRAM…`: it runs the program on the processors and
/// memory its options name.
pub(super) fn numactl(args: &[Arg]) -> Launch {
    Table {
        values: &[
            "-i",
            "--interleave",
            "-w",
            "--weighted-interleave",
            "-m",
            "--membind",
            "-p",
            "--preferred",
            "-P",
            "--preferred-many",
            "-N",
            "-n",
            "--cpunodebind",
            "-C",
            "--physcpubind",
            "-S",
            "--shm",
            "-f",
            "--file",
            "-L",
            "--length",
            "-o",
            "--offset",
            "-I",
            "--shmid",
            "-M",
            "--shmmode",
        ],
        flags: &[
            "-a",
            "--all",
            "-b",
            "--balancing",
            "-l",
            "--localalloc",
            "-s",
            "--show",
            "-H",
            "--hardware",
            "-V",
            "--verify",
            "-t",
            "--huge",
            "-T",
            "--touch",
            "--strict",
        ],
    }
    .after(args, 0)
}

/// libcgroup's `cgexec [-g CONTROLLERS:PATH] [--sticky] PROGRAM…`.
pub(super) fn cgexec(args: &[Arg]) -> Launch {
    Table {
        values: &["-g"],
        flags: &["--sticky", "-h"],
    }
    .after(args, 0)
}

/// `capsh [OPTIONS] [-- ARGS…]`: its options are each one word
/// (`--caps=…`, `--user=…`), and the words after `--` are handed to bash, or
/// to the shell `--shell=` names (`capsh -- -c 'cmd'` runs `bash -c
/// 'cmd'`); `==` runs capsh again with the words after it.
pub(super) fn capsh(unit: &Unit) -> Launch {
    let args = &unit.args;
    let mut shell = "/bin/bash".to_string();
    for (at, arg) in args.iter().enumerate() {
        let Some(text) = arg.known() else {
            if arg.text().starts_with("--") && arg.text().contains('=') {
                continue;
            }
            return Launch::Opaque(UNKNOWN_WORD);
        };
        let program = match text {
            "--" => shell.clone(),
            "==" => "capsh".to_string(),
            _ => {
                if let Some(value) = text.strip_prefix("--shell=") {
                    value.clone_into(&mut shell);
                }
                if text.starts_with("--") {
                    continue;
                }
                return Launch::Itself;
            }
        };
        let mut run = running(unit, "capsh", at);
        run.program = Arg::Known(program);
        return Launch::Replace(Box::new(run));
    }
    Launch::Itself
}

/// `gosu USER PROGRAM…` and `su-exec USER PROGRAM…` run the program as the
/// user.
pub(super) fn as_user(args: &[Arg]) -> Launch {
    match args.first().and_then(Arg::known) {
        Some(first) if first.starts_with('-') => Launch::Itself,
        _ => runs(args, Some(1)),
    }
}

/// runit's `chpst [OPTIONS] PROGRAM…`: its options read as `getopt` reads
/// them; `-C DIR` starts the program in `DIR`, and `-/ ROOT` in a file
/// system rooted at `ROOT`, so a path it names may be any folder.
pub(super) fn chpst(args: &[Arg]) -> Launch {
    const VALUED: &str = "uUbe/CnlLmdopfcrt";
    let start = after_getopt(args, VALUED, &[]);
    let program = runs(args, start);
    let own = args.get(..start.unwrap_or(args.len())).unwrap_or_default();
    let folder = folder_option(own, &["-C"], true, |text, _| getopt_word(text, VALUED, &[]));
    let rooted = own
        .iter()
        .filter_map(Arg::known)
        .any(|text| text.starts_with("-/"));
    let program = in_folder(folder, program);
    if rooted {
        mapped(program)
    } else {
        program
    }
}

/// daemontools' and runit's programs that run the program after a word of
/// their own: `setuidgid USER`, `envuidgid USER`, `envdir DIR` (whose files
/// set its environment), `softlimit [OPTIONS]`, `setlock [-nNxX] FILE` and
/// `pgrphack`.
pub(super) fn daemontools(key: &str, args: &[Arg]) -> Launch {
    match key {
        "setuidgid" | "envuidgid" | "envdir" => runs(args, Some(1)),
        "softlimit" => runs(args, after_getopt(args, "acdflmoprst", &[])),
        "setlock" => runs(args, after_getopt(args, "", &[]).map(|file| file + 1)),
        _ => runs(args, Some(0)),
    }
}

/// `tini [OPTIONS] [--] PROGRAM…`, an init for containers: `-p` and `-e`
/// take a value.
pub(super) fn tini(args: &[Arg]) -> Launch {
    runs(args, after_getopt(args, "pe", &[]))
}

/// `dumb-init [OPTIONS] PROGRAM…`, an init for containers.
pub(super) fn dumb_init(args: &[Arg]) -> Launch {
    Table {
        values: &["-r", "--rewrite"],
        flags: &[
            "-c",
            "--single-child",
            "-v",
            "--verbose",
            "-V",
            "--version",
            "-h",
            "--help",
        ],
    }
    .after(args, 0)
}

/// `flatpak-spawn [OPTIONS] PROGRAM…` runs the program in a sandbox, or with
/// `--host` outside the one it is in, in the folder `--directory` names.
pub(super) fn flatpak_spawn(args: &[Arg]) -> Launch {
    const TABLE: Table = Table {
        values: &[
            "--forward-fd",
            "--env",
            "--unset-env",
            "--sandbox-expose",
            "--sandbox-expose-ro",
            "--sandbox-expose-path",
            "--sandbox-expose-path-ro",
            "--sandbox-flag",
            "--app-path",
            "--usr-path",
            "--directory",
        ],
        flags: &[
            "--host",
            "--clear-env",
            "--watch-bus",
            "--expose-pids",
            "--share-pids",
            "--latest-version",
            "--no-network",
            "--sandbox",
            "--verbose",
            "-v",
            "--help",
            "-h",
        ],
    };
    let program = TABLE.after(args, 0);
    let Launch::Runs(start) = program else {
        return program;
    };
    let folder = folder_option(&args[..start], &["--directory"], false, |text, _| {
        if TABLE.read(text) == Some(2) {
            Word::Value
        } else {
            Word::Flag
        }
    });
    in_folder(folder, program)
}

/// `distrobox enter [OPTIONS] [NAME] -- COMMAND…` (also `distrobox-enter`,
/// and `-e`, `--exec`, for the `--`): it runs the command in a container
/// that shares the home directory. Without one it opens a shell there.
pub(super) fn distrobox(key: &str, args: &[Arg]) -> Launch {
    let from = usize::from(key == "distrobox");
    if key == "distrobox" && args.first().and_then(Arg::known) != Some("enter") {
        return Launch::Itself;
    }
    args.iter()
        .skip(from)
        .position(|arg| matches!(arg.known(), Some("--" | "-e" | "--exec")))
        .map_or(Launch::Itself, |at| runs(args, Some(from + at + 1)))
}

/// `toolbox [OPTIONS] run [OPTIONS] COMMAND…` runs the command in a
/// container that shares the home directory.
pub(super) fn toolbox(args: &[Arg]) -> Launch {
    const GLOBAL: Table = Table {
        values: &["--log-level"],
        flags: &["-y", "--assumeyes", "--log-podman", "-v", "--verbose"],
    };
    const RUN: Table = Table {
        values: &[
            "-c",
            "--container",
            "-d",
            "--distro",
            "-r",
            "--release",
            "--preserve-fds",
        ],
        flags: &[],
    };
    let Ok(at) = after_known(args, 0, |text| GLOBAL.read(text)) else {
        return Launch::Opaque(UNKNOWN_OPTION);
    };
    if args.get(at).and_then(Arg::known) != Some("run") {
        return Launch::Itself;
    }
    RUN.after(args, at + 1)
}

/// The terminal emulators, which run the command a few options name in a
/// window of their own.
pub(super) const TERMINALS: [&str; 25] = [
    "xterm",
    "uxterm",
    "urxvt",
    "urxvtc",
    "rxvt",
    "rxvt-unicode",
    "st",
    "alacritty",
    "konsole",
    "gnome-terminal",
    "mate-terminal",
    "xfce4-terminal",
    "terminator",
    "tilix",
    "lxterminal",
    "sakura",
    "qterminal",
    "terminology",
    "x-terminal-emulator",
    "kgx",
    "ptyxis",
    "cool-retro-term",
    "guake",
    "eterm",
    "aterm",
];

/// What a terminal emulator runs: the words after `-x`, `--execute` or
/// `--` as a program and its arguments; after `-e`, `--command`, `--exec`
/// or `--execute-command` the same, or the word after it as a command line
/// (terminals differ: xterm and alacritty take the words, gnome-terminal
/// and xfce4-terminal a line), so both are judged; and the line joined to
/// one of those (`--command='…'`).
pub(super) fn terminal(args: &[Arg]) -> Launch {
    for (at, arg) in args.iter().enumerate() {
        let Some(text) = arg.known() else { continue };
        match text {
            "-x" | "--execute" | "--" => return runs(args, Some(at + 1)),
            "-e" | "--command" | "--exec" | "--execute-command" => {
                return match args.get(at + 1) {
                    Some(next) => Launch::Either(
                        Box::new(Launch::Runs(at + 1)),
                        Box::new(Launch::Script(
                            Shell::Posix,
                            next.clone(),
                            Source::arg(next),
                        )),
                    ),
                    None => Launch::Itself,
                };
            }
            _ => {}
        }
        let joined = [
            "--command=",
            "--execute=",
            "--exec=",
            "--execute-command=",
            "-e=",
        ]
        .iter()
        .find_map(|prefix| text.strip_prefix(prefix));
        if let Some(line) = joined {
            return Launch::Script(
                Shell::Posix,
                Arg::Known(line.to_string()),
                Source::part(arg, line),
            );
        }
    }
    Launch::Itself
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_reads_bundles_and_joined_values() {
        let table = Table {
            values: &["-u", "--user"],
            flags: &["-l", "-p"],
        };
        assert_eq!(table.read("-u"), Some(2));
        assert_eq!(table.read("-lu"), Some(2));
        assert_eq!(table.read("-ubob"), Some(1));
        assert_eq!(table.read("-lp"), Some(1));
        assert_eq!(table.read("--user=bob"), Some(1));
        assert_eq!(table.read("-x"), None);
        assert_eq!(table.read("--other"), None);
    }
}
