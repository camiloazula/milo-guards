//! Adding a unit to a split: the wrappers in front of a program come off
//! (`sudo rm` is `rm`, run as root), and a program started with a script
//! (`bash -c`, `cmd /c`, `powershell -Command`, `eval`, `trap`,
//! `Invoke-Expression`) has that script split in its own grammar. A package
//! runner (`npx`, `uvx`, `bunx`) is a wrapper for the program it names.

use crate::dotglob;
use crate::extended;
use crate::inline::{self, Code, Language};
use crate::powershell::Params;
use crate::startup;
use crate::unit::{self, has_flag, Arg, Reads, Split, Unit};
use crate::{Rule, Shell};

mod find;
mod interpreters;
mod npm;
mod wrappers;

use find::find_exec;
pub(crate) use find::find_targets;
pub(crate) use interpreters::{
    after_run, perl_edits, BUN_VALUES, DENO_VALUES, INTERPRETERS, SHELLS,
};
use interpreters::{bun, deno, interpreter, shell, trap, trap_inherited};
use wrappers::{cmd, env, env_sets, powershell, rsh, runner, start, start_process, tmux, xargs};
pub(crate) use wrappers::{powershell_file, uv_script, RUNNERS};

/// How many wrappers may stand in front of a program before the line is
/// too wrapped to read.
const MAX_WRAPPERS: usize = 16;

/// How many times one line may fork into two readings (see
/// [`Launch::Either`]): each fork is one more reading to judge, so this
/// bounds the work whatever the line does. A plain line has none or a few.
const MAX_FORKS: usize = 32;

/// What a program does with the rest of its arguments.
#[derive(PartialEq)]
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
    /// It runs `code`, given inline, in `language`.
    Inline(Language, Code),
    /// It runs a script it downloads.
    Downloaded,
    /// It runs commands the grammar cannot read, said in the reason.
    Opaque(&'static str),
    /// The line reads two ways and each is judged, so the riskier one
    /// counts.
    Either(Box<Launch>, Box<Launch>),
}

pub(crate) fn add(split: &mut Split, unit: Unit, depth: usize) {
    let outer = split.scope_hidden(false);
    // What a wrapper in front of the program sets is the program's only.
    let options = split.node_options.len();
    let paths = split.python_path.len();
    let environment = split.environment;
    add_unit(split, unit, depth);
    split.node_options.truncate(options);
    split.python_path.truncate(paths);
    split.environment = environment;
    split.unscope_hidden(outer);
}

/// Whether the wrapper `key` may hand the program it runs an environment of
/// its own (`env FOO=1`, `sudo FOO=1`, `xargs`): every wrapper but the few
/// that only change how the program runs (`nice`, `timeout`). The words
/// that start a command of their own (`time`, `!`, `{`, zsh's `repeat`)
/// hand it the assignments among `own`, the words before it (`time FOO=1
/// cmd`).
fn sets_environment(key: &str, own: &[Arg]) -> bool {
    if starts_command(key) {
        return own.iter().filter_map(Arg::known).any(is_assignment);
    }
    !matches!(
        key,
        "nice"
            | "ionice"
            | "nohup"
            | "builtin"
            | "timeout"
            | "gtimeout"
            | "command"
            | "exec"
            | "setsid"
            | "unbuffer"
            | "stdbuf"
            | "caffeinate"
            | "and"
            | "or"
            | "not"
            | "noglob"
            | "nocorrect"
            | "-"
    )
}

/// Whether node, given code inline or from its input, is told to run code
/// from a `data:` URL that is not read: by its own options, or by the
/// `NODE_OPTIONS` it is given. Python is the same when `PYTHONPATH` puts a
/// folder outside the workspace where its imports look.
fn loads_foreign(key: &str, unit: &Unit, split: &Split) -> bool {
    match inline::language(key) {
        Some(Language::JavaScript) if matches!(key, "node" | "nodejs") => {
            inline::loads_foreign_code(&unit.args)
                || inline::options_load_foreign_code(&split.node_options)
        }
        Some(Language::Python) => inline::path_loads_foreign_code(&split.python_path),
        _ => false,
    }
}

/// Add `unit`, and `other` as a second reading of it: the same command with
/// its words read as zsh reads them with `extendedglob` on. Each is judged,
/// so the riskier counts; a fork, as [`Launch::Either`] makes, so a line past
/// [`MAX_FORKS`] of them is unreadable.
pub(crate) fn add_either(split: &mut Split, unit: Unit, other: Unit, depth: usize) {
    if !split.fork(MAX_FORKS) {
        split.problem(
            Rule::Unreadable,
            "reads in too many ways to judge each",
            Some(unit.program.text()),
        );
        add(split, unit, depth);
        return;
    }
    add(split, unit, depth);
    add(split, other, depth);
}

fn add_unit(split: &mut Split, unit: Unit, depth: usize) {
    add_launched(split, unit, depth, MAX_WRAPPERS, None);
}

/// [`add_unit`], where at most `wrappers` more may come off and the first
/// launch is `given` when there is one (one reading of a line that
/// [`Launch::Either`] reads two ways). Both readings share the wrappers
/// left, so a line past them is too wrapped however it forks.
fn add_launched(
    split: &mut Split,
    mut unit: Unit,
    depth: usize,
    wrappers: usize,
    given: Option<Launch>,
) {
    unit.depth = depth;
    let mut given = given;
    for used in 0..wrappers {
        // `env GLOBIGNORE=x bash -c '…'` hands the option to what it runs.
        if unit.args.iter().any(dotglob::assigns_hiding) {
            split.scope_hidden(true);
        }
        if unit.shell == Shell::Posix {
            if let Some(program) = unit.program.known() {
                // `command {rm,-rf,~}`: the shell spells the list out into
                // words, and the first is the program.
                if crate::path::brace_expansion(program) {
                    split.problem(
                        Rule::Unreadable,
                        "runs a program a brace list names, which cannot be read",
                        Some(program),
                    );
                    split.push(unit);
                    return;
                }
                // `env ./* -rf /`: the first name a wildcard matches is the
                // program. Where nothing wraps the program, the line's own
                // grammar has said whether its wildcard is quoted.
                if !unit.wrappers.is_empty() && unit::pattern(program) {
                    unit.program = Arg::Unknown(program.to_string());
                }
            }
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
        let launched = given.take().unwrap_or_else(|| launch(&key, &unit));
        // `env X=1 cmd` and `env -u X cmd` change the program's environment,
        // as `coproc X=1 cmd` and `time X=1 cmd` do.
        if split.kept.on && unit.shell != Shell::Cmd {
            let names = match key.as_str() {
                "env" => env_sets(&unit.args),
                key if unit.shell == Shell::Posix && (key == "coproc" || starts_command(key)) => {
                    assigned_before(&unit.args, &launched)
                }
                _ => Vec::new(),
            };
            for name in names {
                split.set(&name);
            }
        }
        match launched {
            Launch::Either(first, second) => {
                if !split.fork(MAX_FORKS) {
                    split.problem(
                        Rule::Unreadable,
                        "reads in too many ways to judge each",
                        Some(unit.program.text()),
                    );
                    split.push(unit);
                    return;
                }
                let left = wrappers - used;
                add_launched(split, unit.clone(), depth, left, Some(*first));
                add_launched(split, unit, depth, left, Some(*second));
                return;
            }
            Launch::Itself => {
                // What `find` picks is handed to the programs its `-exec` runs.
                let first = split.units.len();
                if key == "find" && unit.shell == Shell::Posix {
                    find_exec(split, &unit, depth);
                }
                let execs = first..split.units.len();
                let at = split.units.len();
                split.push(unit);
                split.nest(execs, at..at + 1);
                return;
            }
            Launch::Runs(start) => {
                note_wrapper(split, &key, &unit, start);
                let own = unit.args.get(..start).unwrap_or_default();
                split.environment += usize::from(sets_environment(&key, own));
                split
                    .node_options
                    .extend(wrappers::node_options(&unit.args, start));
                split
                    .python_path
                    .extend(wrappers::python_path(&unit.args, start));
                // `env BASH_ENV=f bash`: the shell it starts runs `f`.
                let files = if key == "env" && unit.shell == Shell::Posix {
                    startup::env(split, &unit.args[..start], depth)
                } else {
                    Vec::new()
                };
                unit = inner(unit, key, start, &Hands::Nothing);
                for file in files {
                    if !startup::push(&mut unit.startup, file) {
                        split.startup_overflow();
                    }
                }
            }
            Launch::Input { start, replace } => {
                note_wrapper(split, &key, &unit, start);
                let own = unit.args.get(..start).unwrap_or_default();
                split.environment += usize::from(sets_environment(&key, own));
                split
                    .node_options
                    .extend(wrappers::node_options(&unit.args, start));
                split
                    .python_path
                    .extend(wrappers::python_path(&unit.args, start));
                let hands = replace.map_or(Hands::After, Hands::Where);
                unit = inner(unit, key, start, &hands);
            }
            Launch::Replace(replacement) => {
                // A package runner puts a venv or `node_modules/.bin` on
                // `PATH`, passes npm's config on as environment variables
                // and loads `--env-file`; `bun run` loads `.env`. What it
                // starts has an environment the line does not show.
                split.environment += 1;
                unit = *replacement;
            }
            Launch::Script(shell, script) => {
                // A shell started with the option on (`bash -O dotglob -c`,
                // `zsh -o globdots -c`) runs its script with it on.
                let starts_hidden = SHELLS.contains(&key.as_str())
                    && shell == Shell::Posix
                    && dotglob::starts_with(&unit.args);
                // And `zsh -o extendedglob -c` with zsh's extended patterns.
                let starts_extended = SHELLS.contains(&key.as_str())
                    && shell == Shell::Posix
                    && extended::starts_with(&unit.args);
                let stage = unit.stage;
                let inherited = key == "trap" && trap_inherited(&unit.args);
                let shell_at = split.units.len();
                split.push(unit);
                // A `trap` action in double quotes is expanded when the trap
                // is set and its result read as code when it runs, as
                // `eval "…"` does: whatever an expansion holds becomes code.
                // The text around the expansions is still read.
                let mut source = None;
                let script = match script {
                    Arg::Template {
                        text,
                        source: written,
                    } if key == "trap" => {
                        split.problem(
                            Rule::Unknown,
                            "runs a script only known when it runs",
                            Some(&written),
                        );
                        source = Some(written);
                        Arg::Known(text)
                    }
                    other => other,
                };
                match script {
                    Arg::Known(text) => {
                        // A script in a process of its own sets its options
                        // for itself; `eval` and `trap` run in this shell,
                        // or in a subshell when they are a stage of a
                        // pipeline, which can turn the option on but not
                        // off. A `GLOBIGNORE` in front of any is in its
                        // environment.
                        let outer = split.hidden_snapshot();
                        if starts_hidden || split.scoped_hidden() {
                            split.hide_for_script();
                        }
                        if starts_extended {
                            split.extend_glob();
                        }
                        // A `trap`'s script runs later: when the line ends,
                        // or between its commands. It is a body, judged with
                        // the option on if the line ever turns it on, and
                        // nothing in it is certain to run before the line's
                        // next unit.
                        let later = (key == "trap").then(|| {
                            split.branches += 1;
                            split.bodies += 1;
                            split.begin_later()
                        });
                        // `eval` runs in this shell: a `cd` in it moves the rest
                        // of the line. In a pipeline only zsh's last stage
                        // does, but as for a `cd` the guard counts any stage.
                        // PowerShell's `Invoke-Expression` runs its string in
                        // the session, which has one location.
                        let here = key == "eval" || key == "invoke-expression";
                        unit::script_in(split, &text, shell, depth + 1, here);
                        // What the script runs, it runs for the shell that started it.
                        split.nest(shell_at..shell_at + 1, shell_at + 1..split.units.len());
                        if let Some(began) = later {
                            split.branches -= 1;
                            split.bodies -= 1;
                            if let Some(source) = &source {
                                split.show_source(began, source);
                            }
                            split.end_later(began, inherited);
                        }
                        if !matches!(key.as_str(), "eval" | "trap") {
                            split.restore_hidden(outer);
                        } else if stage.is_some() {
                            split.restore_hidden(outer.or(split.hidden_snapshot()));
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
            Launch::Inline(language, code) => {
                // The paths in the code are read as POSIX ones, and a command it
                // runs as a POSIX shell line: on Windows they are neither.
                if unit.shell != Shell::Posix {
                    unit.reads = Reads::Interpreter;
                    split.push(unit);
                    return;
                }
                // Code node is told to run from a `data:` URL first is not read.
                if loads_foreign(&key, &unit, split) {
                    unit.reads = Reads::Interpreter;
                    split.push(unit);
                    return;
                }
                split.push(unit);
                inline::apply_all(split, language, &code, depth + 1);
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
            Launch::Downloaded => {
                split.problem(Rule::RunDownloaded, "runs a downloaded script", None);
                split.push(unit);
                return;
            }
            Launch::Reads(reads) => {
                // An interpreter given a here-document or here-string of plain
                // text reads that as its code, unless node is also told to load
                // code from a `data:` URL first: that code runs and is not read,
                // so the line stays unknown whatever its input holds.
                let data = loads_foreign(&key, &unit, split);
                let source = match (reads, inline::language(&key), &unit.stdin) {
                    (Reads::Interpreter, Some(language), Some(Arg::Known(code))) if !data => {
                        Some((language, code.clone()))
                    }
                    _ => None,
                };
                if let Some((language, code)) = source {
                    split.push(unit);
                    inline::apply_input(split, language, &code, depth + 1);
                    return;
                }
                unit.reads = reads;
                split.push(unit);
                return;
            }
            Launch::Opaque(reason) => {
                split.problem(Rule::Unreadable, reason, Some(unit.program.text()));
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

/// Say what the options of the wrapper `key`, the arguments before the
/// program at `start`, do: `time -o FILE` writes, an option the guard does
/// not know is not read. For `effect` only.
fn note_wrapper(split: &mut Split, key: &str, unit: &Unit, start: usize) {
    if split.kept.on {
        let own = unit.args.get(..start).unwrap_or_default();
        split.wrapped(crate::effect::wrapper(key, own));
    }
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
        stdin,
        startup,
        depth,
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
        stdin,
        dir: None,
        elsewhere: Vec::new(),
        stayed: Vec::new(),
        hidden: false,
        startup,
        repeated: false,
        downloaded: false,
        relocates: false,
        listings: Vec::new(),
        unread_item: false,
        listed: Vec::new(),
        depth,
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
        // bash's and zsh's `time` times a whole command, which may be a
        // group or a negation the grammar does not read after it (`time {
        // cmd; }`, `time ! cmd`, `time X=1 cmd`).
        "time" if posix => {
            let start = after_options(args, &["-f", "-o", "--format", "--output"]);
            match start {
                Some(start) if unit.shell == Shell::Posix => command_after(args, start, false),
                start => runs(args, start),
            }
        }
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
        // zsh's precommand modifiers `noglob`, `nocorrect` and `-` take no
        // options: the next word is the program (`noglob -- rm` runs a
        // program named `--`). A POSIX program of one of these names is rare
        // enough to read the same way.
        "noglob" | "nocorrect" | "-" if unit.shell == Shell::Posix => runs(args, Some(0)),
        // `coproc` starts a command in the background. A simple command
        // takes no name (`coproc NAME cmd` runs a program called `NAME`),
        // a group may: `coproc { cmd; }`, `coproc NAME { cmd; }`. The
        // grammar has no `coproc`, so a group reads as the word `{` and the
        // commands after it, and what comes after is judged as it is.
        "coproc" if unit.shell == Shell::Posix => coproc(args),
        // The grammar does not read a group or a negation after a word that
        // starts a command of its own (`time`, `!`, `coproc`, zsh's
        // `repeat`): `{` and `!` are then programs, and the command after
        // them is what runs (`! { cmd; }`).
        key if unit.shell == Shell::Posix && (key == "!" || opens_group(key)) => {
            command_after(args, 0, false)
        }
        // zsh's `repeat N` runs the command or group after the count N
        // times, or the list between `do` and `done`.
        "repeat" if unit.shell == Shell::Posix => match args.first() {
            Some(_) => command_after(args, 1, true),
            None => Launch::Itself,
        },
        // A loop, a conditional or a function the grammar cut into pieces
        // (`! for …; do …; done`, `time if …`), its body behind the program
        // `do` or `then`.
        key if unit.shell == Shell::Posix && COMPOUND.contains(&key) => {
            Launch::Opaque("starts a compound command that cannot be read")
        }
        // The body of a loop or a conditional the grammar cut off from the
        // words that open it: zsh's `repeat 3; do cmd; done` (zsh skips the
        // separators after the count), or a loop after `time` or `!`. A
        // line the shell runs never has a program of these names.
        key if unit.shell == Shell::Posix && BODY.contains(&key) => {
            Launch::Opaque("runs the body of a loop or a conditional that cannot be read")
        }
        // A `{` stuck to a word (`! {rm -rf ~;}`): zsh runs a group, the
        // grammar reads a program of that name.
        key if unit.shell == Shell::Posix && key.starts_with('{') => {
            Launch::Opaque("starts a group whose commands cannot be read")
        }
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
        "trap" if unit.shell == Shell::Posix => trap(args),
        "source" | "." if unit.shell == Shell::Posix => match args.first() {
            Some(Arg::Known(script)) if is_stdin(script) => Launch::Reads(Reads::Shell),
            Some(Arg::Known(_)) | None => Launch::Itself,
            Some(script) => Launch::Script(Shell::Posix, script.clone()),
        },
        // Package runners start the program they name.
        "npx" | "npm" | "pnpm" | "pnpx" | "pnx" | "yarn" | "bunx" | "uvx" | "uv" | "pipx" => {
            runner(key, unit)
        }
        "dx" => runner(key, unit),
        "bun" => bun(unit),
        "deno" => deno(unit),
        key if SHELLS.contains(&key) && posix => shell(args),
        // Also under cmd and PowerShell: the code they are given is not
        // read there, which comes back as `unknown`. A line with nothing to
        // run (`python --version`, a bare `python`) reads its input only
        // where it did before: under any but cmd, and anywhere when
        // something is piped into it.
        key if INTERPRETERS.contains(&key) || key.starts_with("python3.") => {
            interpreter(key, args, posix || piped(unit))
        }
        "cmd" => cmd(args),
        "powershell" | "pwsh" => powershell(args),
        "invoke-expression" if unit.shell == Shell::PowerShell && unit.downloaded => {
            Launch::Downloaded
        }
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

/// Whether another program's output is piped into the unit.
fn piped(unit: &Unit) -> bool {
    unit.stage.is_some_and(|stage| stage.index > 0)
}

/// What `coproc` runs: the first word past an optional name, the `{` words
/// that open a group (`coproc NAME { { cmd; }; }`), and what stands before a
/// command (`NAME=value` words, `!`). A loop, a conditional or a function
/// after it (`coproc while …; do …; done`, also inside a group) is cut into
/// pieces by the grammar, its body behind the program `do`, so it is not
/// read.
fn coproc(args: &[Arg]) -> Launch {
    let word = |at: usize| args.get(at).and_then(Arg::known);
    let opens = |at: usize| word(at).is_some_and(opens_group);
    let compound = |at: usize| word(at).is_some_and(|text| COMPOUND.contains(&text));
    let stuck = |at: usize| word(at).is_some_and(stuck_group);
    // A name stands before a group or a compound command; before a simple
    // command the first word is the program.
    let at = usize::from(!opens(0) && !stuck(0) && (opens(1) || stuck(1) || compound(1)));
    command_after(args, at, false)
}

/// What runs after a word that starts a command of its own (`coproc`,
/// `time`, `!`, `{`, zsh's `repeat`), from the word at `at`: the first word
/// past the `{` words that open a group, `!` and `NAME=value` words, and,
/// after `repeat`, the `do` that opens its list. A loop, a conditional or a
/// function there (`time for …; do …; done`, also inside a group) is cut
/// into pieces by the grammar, its body behind the program `do`, so it is
/// not read; nor is a group whose `{` is stuck to a word (`{rm`), a group
/// zsh runs that the grammar reads as a program.
fn command_after(args: &[Arg], mut at: usize, repeat: bool) -> Launch {
    let word = |at: usize| args.get(at).and_then(Arg::known);
    while word(at).is_some_and(|text| {
        opens_group(text) || text == "!" || is_assignment(text) || (repeat && text == "do")
    }) {
        at += 1;
    }
    if word(at).is_some_and(|text| COMPOUND.contains(&text)) {
        Launch::Opaque("starts a compound command that cannot be read")
    } else if word(at).is_some_and(stuck_group) {
        Launch::Opaque("starts a group whose commands cannot be read")
    } else {
        runs(args, Some(at))
    }
}

/// Whether `key` is a word that starts a command of its own, which the
/// grammar reads as a program: bash's and zsh's `time`, `!`, the `{` of a
/// group, zsh's `repeat`.
fn starts_command(key: &str) -> bool {
    matches!(key, "time" | "!" | "repeat") || opens_group(key)
}

/// Whether `text` is a `{` stuck to a word (`{rm`), which zsh runs as a
/// group and the grammar reads as one word.
fn stuck_group(text: &str) -> bool {
    text.starts_with('{') && !opens_group(text)
}

/// The words that open a compound command with a body of its own.
const COMPOUND: [&str; 7] = ["while", "until", "if", "for", "select", "case", "function"];

/// The words that open the body of a loop or a branch of a conditional.
const BODY: [&str; 4] = ["do", "then", "elif", "else"];

/// Whether `text` is the `{` of a group, or several of them in one word: the
/// grammar reads `{ {` as one.
pub(crate) fn opens_group(text: &str) -> bool {
    text.starts_with('{') && text.chars().all(|c| c == '{' || c.is_whitespace())
}

/// Whether `text` is a `NAME=value` assignment, which the shell takes off
/// before the command (`NAME+=value` and `NAME[i]=value` too).
fn is_assignment(text: &str) -> bool {
    let Some((name, _)) = text.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let name = name.split_once('[').map_or(name, |(name, _)| name);
    name.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The variables a `coproc`, `time`, `!` or `{` sets for the command it
/// runs, the assignments before the program `launched` starts, for
/// `effect`.
fn assigned_before(args: &[Arg], launched: &Launch) -> Vec<String> {
    let Launch::Runs(start) = *launched else {
        return Vec::new();
    };
    args.get(..start)
        .unwrap_or_default()
        .iter()
        .filter_map(Arg::known)
        .filter(|text| is_assignment(text))
        .filter_map(|text| text.split(['=', '+', '[']).next())
        .map(str::to_string)
        .collect()
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
    after_options_by(args, |text, _| {
        if values.contains(&text) {
            Word::Value
        } else {
            Word::Flag
        }
    })
}

/// What a word that starts with a dash is, among a wrapper's options.
pub(super) enum Word {
    /// An option that takes nothing more.
    Flag,
    /// An option that takes the next argument as its value.
    Value,
    /// Not an option at all: the wrapper reads it as the program (or an
    /// operand), whatever it looks like.
    Operand,
}

/// [`after_options`] for a wrapper that reads its options by a rule of its
/// own: `read` is given each word that starts with a dash and the word after
/// it.
pub(super) fn after_options_by(
    args: &[Arg],
    read: impl Fn(&str, Option<&Arg>) -> Word,
) -> Option<usize> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => return (at + 1 < args.len()).then_some(at + 1),
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                at += match read(text, args.get(at + 1)) {
                    Word::Flag => 1,
                    Word::Value => 2,
                    Word::Operand => return Some(at),
                };
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
