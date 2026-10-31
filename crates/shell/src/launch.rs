//! Adding a unit to a split: the wrappers in front of a program come off
//! (`sudo rm` is `rm`, run as root), and a program started with a script
//! (`bash -c`, `cmd /c`, `powershell -Command`, `eval`,
//! `Invoke-Expression`) has that script split in its own grammar.

use crate::dotglob;
use crate::powershell::Params;
use crate::unit::{self, has_flag, Arg, Reads, Split, Unit};
use crate::{Rule, Shell};

mod find;
mod interpreters;
mod wrappers;

use find::find_exec;
pub(crate) use find::find_targets;
use interpreters::{interpreter, shell};
pub(crate) use interpreters::{perl_edits, INTERPRETERS, SHELLS};
use wrappers::{cmd, env, powershell, rsh, start, start_process, tmux, xargs};

/// How many wrappers may stand in front of a program before the line is
/// too wrapped to read.
const MAX_WRAPPERS: usize = 16;

/// What a program does with the rest of its arguments.
pub(super) enum Launch {
    /// It is the program the rules judge.
    Itself,
    /// It runs the program at `start` with the arguments after it.
    Runs(usize),
    /// `xargs`: it runs the program at `start` with what its input gives,
    /// put where `replace` stands or after the arguments.
    Input {
        start: usize,
        replace: Option<String>,
    },
    /// It runs another unit, built from its own parameters.
    Replace(Box<Unit>),
    /// It runs `script` in `shell`.
    Script(Shell, Arg),
    /// It runs a script given encoded.
    Encoded,
    /// It reads its commands from its input.
    Reads(Reads),
}

pub(crate) fn add(split: &mut Split, unit: Unit, depth: usize) {
    let outer = split.scope_hidden(false);
    add_unit(split, unit, depth);
    split.unscope_hidden(outer);
}

fn add_unit(split: &mut Split, mut unit: Unit, depth: usize) {
    for _ in 0..MAX_WRAPPERS {
        // `env GLOBIGNORE=x bash -c '…'` hands the option to what it runs.
        if unit.args.iter().any(dotglob::assigns_globignore) {
            split.scope_hidden(true);
        }
        let Some(key) = unit.key() else {
            split.problem(
                Rule::Unknown,
                "runs a program only known when it runs",
                Some(unit.program.text()),
            );
            split.push(unit);
            return;
        };
        match launch(&key, &unit) {
            Launch::Itself => {
                if key == "find" && unit.shell == Shell::Posix {
                    find_exec(split, &unit, depth);
                }
                split.push(unit);
                return;
            }
            Launch::Runs(start) => unit = inner(unit, key, start, &Hands::Nothing),
            Launch::Input { start, replace } => {
                let hands = replace.map_or(Hands::After, Hands::Where);
                unit = inner(unit, key, start, &hands);
            }
            Launch::Replace(replacement) => unit = *replacement,
            Launch::Script(shell, script) => {
                split.push(unit);
                match script {
                    Arg::Known(text) => {
                        // A script in a process of its own sets its options
                        // for itself; `eval` runs in this shell. A
                        // `GLOBIGNORE` in front of either is in its
                        // environment.
                        let outer = split.hidden_snapshot();
                        if split.scoped_hidden() {
                            split.hide();
                        }
                        unit::script(split, &text, shell, depth + 1);
                        if key != "eval" {
                            split.restore_hidden(outer);
                        }
                    }
                    other => split.problem(
                        Rule::Unknown,
                        "runs a script only known when it runs",
                        Some(other.text()),
                    ),
                }
                return;
            }
            Launch::Encoded => {
                split.problem(
                    Rule::Unknown,
                    "runs an encoded script that cannot be read",
                    None,
                );
                split.push(unit);
                return;
            }
            Launch::Reads(reads) => {
                unit.reads = reads;
                split.push(unit);
                return;
            }
        }
    }
    split.problem(
        Rule::Unreadable,
        "wraps a program in too many others to read",
        None,
    );
    split.push(unit);
}

/// What a wrapper hands the program it runs, besides its arguments.
enum Hands {
    Nothing,
    /// Its input, after the arguments (`xargs rm`).
    After,
    /// Its input, in each argument holding this text (`xargs -I{} rm {}`).
    Where(String),
}

/// The unit a wrapper named `key` runs: the program at `start`, handed what
/// `hands` says.
fn inner(unit: Unit, key: String, start: usize, hands: &Hands) -> Unit {
    let Unit {
        shell,
        args,
        mut wrappers,
        stage,
        ..
    } = unit;
    let mut rest = args.into_iter().skip(start);
    let program = rest.next().unwrap_or(Arg::Unknown(String::new()));
    let mut args: Vec<Arg> = rest.collect();
    match hands {
        Hands::Where(replace) => {
            for arg in &mut args {
                if arg
                    .known()
                    .is_some_and(|text| text.contains(replace.as_str()))
                {
                    *arg = Arg::Input;
                }
            }
        }
        Hands::After => args.push(Arg::Input),
        Hands::Nothing => {}
    }
    wrappers.push(key);
    Unit {
        shell,
        program,
        args,
        wrappers,
        stage,
        reads: Reads::Nothing,
        dir: None,
        hidden: false,
    }
}

fn launch(key: &str, unit: &Unit) -> Launch {
    let args = &unit.args;
    let posix = unit.shell != Shell::Cmd;
    match key {
        "sudo" | "doas" | "gsudo" | "pkexec" => runs(
            args,
            after_options(
                args,
                &[
                    "-u",
                    "-g",
                    "-h",
                    "-p",
                    "-C",
                    "-D",
                    "-r",
                    "-t",
                    "-U",
                    "-T",
                    "-R",
                    "--user",
                    "--group",
                    "--host",
                    "--prompt",
                    "--chdir",
                    "--role",
                    "--type",
                    "--other-user",
                    "--close-from",
                    "--command-timeout",
                ],
            ),
        ),
        // systemd's own `sudo`, and a command started as a transient unit.
        "run0" if posix => runs(
            args,
            after_options(
                args,
                &[
                    "-u",
                    "-g",
                    "-D",
                    "--user",
                    "--group",
                    "--chdir",
                    "--setenv",
                    "--property",
                    "--description",
                    "--slice",
                    "--unit",
                    "--nice",
                    "--machine",
                ],
            ),
        ),
        "systemd-run" if posix => runs(
            args,
            after_options(
                args,
                &[
                    "-u",
                    "-p",
                    "-E",
                    "-M",
                    "-H",
                    "--unit",
                    "--property",
                    "--setenv",
                    "--machine",
                    "--host",
                    "--description",
                    "--slice",
                    "--uid",
                    "--gid",
                    "--nice",
                    "--working-directory",
                    "--on-active",
                    "--on-boot",
                    "--on-startup",
                    "--on-unit-active",
                    "--on-unit-inactive",
                    "--on-calendar",
                    "--timer-property",
                    "--path-property",
                    "--socket-property",
                    "--service-type",
                ],
            ),
        ),
        // `rsync -e CMD` runs CMD here to reach the other side.
        "rsync" if posix => rsh(args).map_or(Launch::Itself, |command| {
            Launch::Script(Shell::Posix, command)
        }),
        "su" => option_value(args, "-c", "--command").map_or(Launch::Itself, |script| {
            Launch::Script(Shell::Posix, script)
        }),
        "env" if posix => env(args),
        "nice" if posix => runs(args, after_options(args, &["-n", "--adjustment"])),
        "ionice" if posix => runs(
            args,
            after_options(args, &["-c", "-n", "-p", "-t", "--class", "--classdata"]),
        ),
        "nohup" | "builtin" | "unbuffer" | "setsid" if posix => {
            runs(args, after_options(args, &[]))
        }
        "time" if posix => runs(
            args,
            after_options(args, &["-f", "-o", "--format", "--output"]),
        ),
        "timeout" | "gtimeout" if posix => runs(
            args,
            after_options(args, &["-s", "-k", "--signal", "--kill-after"])
                .map(|duration| duration + 1),
        ),
        "stdbuf" if posix => runs(args, after_options(args, &["-i", "-o", "-e"])),
        "caffeinate" if posix => runs(args, after_options(args, &["-t", "-w"])),
        "chroot" if posix => runs(args, after_options(args, &[]).map(|root| root + 1)),
        "exec" if unit.shell == Shell::Posix => runs(args, after_options(args, &["-a"])),
        "command" if unit.shell == Shell::Posix => {
            if has_flag(args, Some('v'), None) || has_flag(args, Some('V'), None) {
                Launch::Itself
            } else {
                runs(args, after_options(args, &[]))
            }
        }
        "xargs" if posix => xargs(args),
        // `busybox rm …` runs its applet: the applet is the program.
        "busybox" if posix => runs(args, after_options(args, &[])),
        // fish chains commands with `; and cmd`, `; or cmd` and `not cmd`;
        // read with the POSIX grammar, the word is the program and the
        // command its arguments. A POSIX program with one of these names is
        // rare enough to read the same way.
        "and" | "or" | "not" if unit.shell == Shell::Posix => runs(args, Some(0)),
        "flock" if posix => option_value(args, "-c", "--command").map_or_else(
            || {
                runs(
                    args,
                    after_options(args, &["-w", "--timeout", "-E", "--conflict-exit-code"])
                        .map(|file| file + 1),
                )
            },
            |script| Launch::Script(Shell::Posix, script),
        ),
        "taskset" if posix => runs(
            args,
            after_options(args, &["-c", "--cpu-list"]).map(|mask| mask + 1),
        ),
        "chrt" if posix => runs(
            args,
            after_options(
                args,
                &[
                    "-T",
                    "--sched-runtime",
                    "-P",
                    "--sched-period",
                    "-D",
                    "--sched-deadline",
                ],
            )
            .map(|prio| prio + 1),
        ),
        "setarch" | "arch" if posix => runs(args, after_options(args, &[])),
        "unshare" if posix => runs(
            args,
            after_options(
                args,
                &[
                    "--map-user",
                    "--map-group",
                    "-S",
                    "--setuid",
                    "-G",
                    "--setgid",
                    "--wd",
                    "--propagation",
                ],
            ),
        ),
        "prlimit" if posix => runs(args, after_options(args, &[])),
        "xcrun" if posix => runs(
            args,
            after_options(args, &["--sdk", "-sdk", "--toolchain", "-toolchain"]),
        ),
        "screen" if posix => runs(
            args,
            after_options(args, &["-S", "-p", "-t", "-c", "-s", "-e", "-T"]),
        ),
        "tmux" if posix => tmux(args),
        // `at`/`batch` run the commands piped into them through a shell.
        "at" | "batch" if posix => Launch::Reads(Reads::Shell),
        "watch" if posix => {
            let start = after_options(args, &["-n", "--interval"]);
            match start {
                Some(start) if has_flag(args, Some('x'), Some("exec")) => Launch::Runs(start),
                Some(start) => Launch::Script(Shell::Posix, join(&args[start..])),
                None => Launch::Itself,
            }
        }
        "eval" if unit.shell == Shell::Posix => Launch::Script(Shell::Posix, join(args)),
        "source" | "." if unit.shell == Shell::Posix => match args.first() {
            Some(Arg::Known(script)) if is_stdin(script) => Launch::Reads(Reads::Shell),
            Some(Arg::Known(_)) | None => Launch::Itself,
            Some(script) => Launch::Script(Shell::Posix, script.clone()),
        },
        key if SHELLS.contains(&key) && posix => shell(args),
        key if posix && (INTERPRETERS.contains(&key) || key.starts_with("python3.")) => {
            interpreter(key, args)
        }
        "cmd" => cmd(args),
        "powershell" | "pwsh" => powershell(args),
        "invoke-expression" if unit.shell == Shell::PowerShell => {
            let params = Params::read(args);
            match params
                .values(&["command"])
                .first()
                .or(params.positional.first())
            {
                Some(script) => Launch::Script(Shell::PowerShell, (*script).clone()),
                None => Launch::Reads(Reads::Shell),
            }
        }
        "start-process" if unit.shell == Shell::PowerShell => start_process(unit),
        "start" if unit.shell == Shell::Cmd => start(args),
        "runas" => match unit::plain(args).last() {
            Some(program) => Launch::Script(Shell::Cmd, (*program).clone()),
            None => Launch::Itself,
        },
        _ => Launch::Itself,
    }
}

/// A script path that is the program's own input: what is piped into it.
pub(super) fn is_stdin(path: &str) -> bool {
    matches!(path, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
}

pub(super) fn runs(args: &[Arg], start: Option<usize>) -> Launch {
    start
        .filter(|start| *start < args.len())
        .map_or(Launch::Itself, Launch::Runs)
}

/// The index of the first argument after a wrapper's options; `values`
/// names the options that take the next argument as their value.
pub(super) fn after_options(args: &[Arg], values: &[&str]) -> Option<usize> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => return (at + 1 < args.len()).then_some(at + 1),
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                at += if values.contains(&text) { 2 } else { 1 };
            }
            _ => return Some(at),
        }
    }
    None
}

/// The value of `short` or `--long` (also `--long=value`).
pub(super) fn option_value(args: &[Arg], short: &str, long: &str) -> Option<Arg> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == short || text == long {
            return iter.next().cloned();
        }
        if let Some(value) = text
            .strip_prefix(long)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(Arg::Known(value.to_string()));
        }
    }
    None
}

/// Arguments joined back into a line, as `eval`, `cmd /c` and
/// `powershell -Command` join them: with spaces, then read again. Unknown
/// when any part is.
pub(super) fn join(args: &[Arg]) -> Arg {
    let line = args.iter().map(Arg::text).collect::<Vec<_>>().join(" ");
    if args.iter().all(|arg| arg.known().is_some()) {
        Arg::Known(line)
    } else {
        Arg::Unknown(line)
    }
}
