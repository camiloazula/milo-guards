//! Adding a unit to a split: the wrappers in front of a program come off
//! (`sudo rm` is `rm`, run as root), and a program started with a script
//! (`bash -c`, `cmd /c`, `powershell -Command`, `eval`, `trap`,
//! `Invoke-Expression`) has that script split in its own grammar. A package
//! runner (`npx`, `uvx`, `bunx`) is a wrapper for the program it names.

use std::rc::Rc;

use crate::detect::STARTS_NOTHING;
use crate::dotglob;
use crate::extended;
use crate::inline::{self, Code, Language};
use crate::located::Source;
use crate::powershell::Params;
use crate::said::Said;
use crate::startup;
use crate::unit::{self, has_flag, Arg, Reads, Split, Unit};
use crate::{Rule, Shell};

mod find;
mod git;
mod interpreters;
mod launchers;
mod named;
mod nix;
mod npm;
mod packages;
mod parallel;
mod tools;
mod wrappers;

use find::find_exec;
pub(crate) use find::{
    find_may_act_on, find_outputs, find_starts, find_targets, find_unread_primary, FIND_VALUED,
};
pub(crate) use git::{global as git_global, is_long as git_long, is_submodule, Global, Unread};
pub(crate) use interpreters::{
    after_run, cluster, code_options, dashed_options, fish_codes, is_gem, is_interpreter,
    is_ipython, is_irb, is_node, is_python, is_ruby, is_shell, is_ts_node, loads_ruby_libraries,
    long_option, options, own_args, perl_edits, py_picks_three, rake_arguments, rake_options,
    ruby_tail, runs_rake, shell_family, single_dash, valued_options, Dashed, FishCodes, Options,
    BUN_VALUES, DENO_VALUES,
};
use interpreters::{bun, deno, interpreter, shell, trap, trap_inherited};
pub(crate) use named::{command_variable, is_command_variable};
use wrappers::{
    cmd, env, env_sets, folder_option, getopt, in_folder, powershell, rsh, runner, start,
    start_process, tmux, xargs, Getopt,
};
pub(crate) use wrappers::{
    gem_config_files, powershell_file, ruby_moved, uv_script, MOST_MOVES, RUNNERS,
};

/// How many wrappers may stand in front of a program before the line is
/// too wrapped to read.
const MAX_WRAPPERS: usize = 16;

/// How many times one line may fork into two readings (see
/// [`Launch::Either`]): each fork is one more reading to judge, so this
/// bounds the work whatever the line does. A plain line has none or a few.
const MAX_FORKS: usize = 32;

/// The most commands a line may give fish in all, nested ones too, when each
/// unit gives it more than one: each is read alone and with the others.
const MAX_FISH_CODES: usize = 16;

/// What a program does with the rest of its arguments.
#[derive(Clone, PartialEq)]
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
    /// It runs `script` in `shell`; the [`Source`] says which of its
    /// arguments the script is, for the ranges of the line's findings.
    Script(Shell, Arg, Source),
    /// It runs `script` in `shell`, in a folder of its own choosing that
    /// the line does not say (`git submodule foreach`).
    Elsewhere(Shell, Arg, Source),
    /// It runs a script given encoded.
    Encoded,
    /// It reads its commands from its input.
    Reads(Reads),
    /// It is the program the rules judge, and it runs each of these
    /// commands through `shell` besides (`tar --to-command`, `zip -TT`),
    /// from a folder only known when it runs when `moves` (`tar -C`).
    Commands {
        shell: Shell,
        commands: Vec<Arg>,
        moves: bool,
    },
    /// It runs `code`, given inline, in `language`.
    Inline(Language, Code),
    /// It runs a script it downloads.
    Downloaded,
    /// It runs a script only known when it runs: a variable, a substitution,
    /// a process substitution, which is a download when what it runs
    /// downloads (`python3 <(curl …)`).
    Unread(Arg),
    /// It runs commands the grammar cannot read, said in the reason.
    Opaque(&'static str),
    /// The line reads two ways and each is judged, so the riskier one
    /// counts.
    Either(Box<Launch>, Box<Launch>),
    /// It does what the inner launch says, started in the folder its own
    /// option names (`env -C DIR`, `pnpm --dir DIR`, `start /d DIR`): what
    /// it runs has its relative paths judged from there, and the rest of
    /// the line from where it was. The folder is read as a path of the
    /// shell given, or of the line's own shell when none is (`wsl --cd`
    /// names a folder of its Linux shell).
    In(Arg, Option<Shell>, Box<Launch>),
}

pub(crate) fn add(split: &mut Split, unit: Unit, depth: usize) {
    let outer = split.scope_hidden(false);
    // What a wrapper in front of the program sets is the program's only,
    // and so is the folder it starts the program in.
    let options = split.node_options.len();
    let paths = split.python_path.len();
    let zip = split.zip_env.clone();
    let variables = split.argument_variables.len();
    let environment = split.environment;
    let folders = split.folders_mark();
    add_unit(split, unit, depth);
    split.leave_folders(folders);
    split.node_options.truncate(options);
    split.python_path.truncate(paths);
    split.zip_env = zip;
    split.truncate_argument_variables(variables);
    split.environment = environment;
    split.unscope_hidden(outer);
}

/// Whether `script`, which the runner `key` of `unit` runs, is the value of
/// a variable the line sets (`npm_config_call`), not text of its own.
fn runs_variable(key: &str, unit: &Unit, script: &Arg) -> bool {
    matches!(key, "npx" | "npm")
        && unit
            .argument_variables
            .iter()
            .any(|(name, value)| unit::npm_call(name) && value == script)
}

/// Add `units`, the readings of one command (cmd's `echo\x.exe` may run
/// `echo` or the file): each is judged, so the riskier one counts. Each of
/// two or more may be the one that does not run, so each is read as a
/// branch: a `cd` among them may not have moved the line (`cd.\a\b.bat`
/// moves it or runs the file).
pub(crate) fn add_readings(split: &mut Split, units: Vec<Unit>, depth: usize) {
    let mut units = units.into_iter();
    let Some(mut first) = units.next() else {
        return;
    };
    let rest: Vec<Unit> = units.collect();
    if rest.is_empty() {
        add(split, first, depth);
        return;
    }
    if !rest.iter().all(|_| split.fork(MAX_FORKS)) {
        first.depth = depth;
        split.problem(
            Rule::Unreadable,
            "reads in too many ways to judge each",
            Some(first.program.text()),
        );
        split.push(first);
        return;
    }
    split.branches += 1;
    add(split, first, depth);
    for unit in rest {
        add(split, unit, depth);
    }
    split.branches -= 1;
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
            | "gtime"
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
        Some(Language::JavaScript) if is_node(key) => {
            inline::loads_foreign_code(&unit.args)
                || inline::options_load_foreign_code(split.node_options.values())
        }
        Some(Language::Python) => inline::path_loads_foreign_code(&split.python_path),
        // `ruby -r lib`, `-I dir`, `-x`: code it loads first, or reads
        // otherwise, which the guard does not read.
        Some(Language::Ruby) => !inline::ruby_reads_input(key, &unit.args),
        _ => false,
    }
}

/// Add `unit`, and each of `others` as another reading of it: the same
/// command with its words read as zsh reads them with `extendedglob` on.
/// Each is judged, so the riskier counts; each is a fork, as
/// [`Launch::Either`] makes, so a line past [`MAX_FORKS`] of them is
/// unreadable.
pub(crate) fn add_either(split: &mut Split, unit: Unit, others: Vec<Unit>, depth: usize) {
    let program = unit.program.text().to_string();
    add(split, unit, depth);
    for other in others {
        if !split.fork(MAX_FORKS) {
            split.problem(
                Rule::Unreadable,
                "reads in too many ways to judge each",
                Some(&program),
            );
            return;
        }
        add(split, other, depth);
    }
}

/// Whether `key`, the program a command runs once its wrappers are off, is
/// one the words of a brace list are not read for: it changes how the shell
/// reads the rest of the line (an option, a variable, a name, the folder), or
/// reads its words again as code (`eval`). Its second reading would make the
/// change twice, or undo what the first made.
fn keeps_its_words(key: &str, unit: &Unit) -> bool {
    match key {
        "shopt" | "setopt" | "unsetopt" | "emulate" | "export" | "declare" | "typeset"
        | "local" | "readonly" | "read" | "mapfile" | "readarray" | "alias" | "unalias"
        | "hash" | "enable" | "unset" | "let" | "eval" | "cd" | "chdir" | "pushd" | "popd" => true,
        // The words after `set --` are only the positional parameters.
        "set" => unit.args.first().and_then(Arg::known) != Some("--"),
        "printf" => unit
            .args
            .iter()
            .filter_map(Arg::known)
            .any(|arg| arg.starts_with("-v")),
        _ => false,
    }
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
        // `alias g=git; g clean -fdx` runs `git clean -fdx`.
        if given.is_none()
            && !unit.aliased
            && unit.shell == Shell::Posix
            && !unit.args.is_empty()
            && unit
                .program
                .known()
                .is_some_and(|name| split.is_alias(name))
            && add_aliased(split, &mut unit, depth, wrappers - used)
        {
            return;
        }
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
        // `ruby -C DIR x.rb` runs the script in another folder.
        if given.is_none() && is_ruby(&key) && ruby_moved(&key, &unit).is_some() {
            split.starts_elsewhere();
        }
        // The words a brace list makes are one more reading of a command,
        // not of one whose own change to the line they would make again or
        // undo (an option it sets, a variable, a folder, a name it defines):
        // it is read as written, and a list in it is unknown.
        if split.spelled_reading && keeps_its_words(&key, &unit) {
            split.unspelled(Some(unit.program.text()));
            return;
        }
        // `ZIPOPT=-m zip …`: zip reads its options from there first, on
        // Windows too (`$env:ZIPOPT`, `set ZIPOPT=`).
        if key == "zip" && !split.zip_env.is_empty() {
            zip_options(split, &mut unit);
        }
        // What the line sets for the program where it runs, which a runner
        // reads (`npm_config_call='…' npx`).
        unit.argument_variables = split.argument_variables.clone();
        let input = fed(&unit) || split.inherits_input > 0;
        // `LD_PRELOAD=x.so cmd`: the program loads a library the line does
        // not show, once for the unit however many ways it reads.
        if given.is_none() && !STARTS_NOTHING.contains(&key.as_str()) {
            if let Some(library) = named::loaded_library(&unit) {
                split.problem(
                    Rule::Unknown,
                    "loads a library into the program",
                    Some(&library),
                );
            }
        }
        // What a tracer, `script` or `time` writes its own output to, once
        // for the unit however many ways it reads.
        if given.is_none() && unit.shell != Shell::Cmd {
            for output in tools::outputs(&key, &unit.args) {
                output_of(split, &unit, output, depth);
            }
        }
        // `repeat 3; do rm -rf build; done`: the `do` the walk read as the
        // list of the `repeat` before it runs the command after it.
        if key == "do" && unit.shell == Shell::Posix && std::mem::take(&mut split.repeat_do) {
            given = Some(command_after(&unit.args, 0, true));
        }
        // A command the line names for the program in a variable it sets or
        // an option (`GIT_SSH_COMMAND='…' git fetch`) runs besides, once for
        // the unit however many ways it reads.
        if given.is_none() && shell_family(&key) == Some("fish") {
            let codes = fish_codes(&unit.args).codes.len();
            if codes > 1 && !split.count_fish_codes(codes, MAX_FISH_CODES) {
                split.problem(
                    Rule::Unknown,
                    "gives fish more commands than are read",
                    Some(unit.program.text()),
                );
                split.push(unit);
                return;
            }
        }
        let launched = if let Some(launched) = given.take() {
            launched
        } else {
            let launched = launch(&key, &unit, input);
            named::with_commands(split, &key, &unit, launched)
        };
        // A runner that sets a project up from a file outside the workspace
        // runs that file's code (`bundle exec --gemfile=/x/Gemfile`, `uv run
        // --project /x`).
        // `time PATH=/tmp/e f`, `repeat 2 PATH=/tmp/e f`: the assignments the
        // word steps over are in front of the command after them.
        if unit.shell == Shell::Posix && (key == "coproc" || key == "do" || starts_command(&key)) {
            note_stepped_assignments(split, &unit.args);
        }
        for (folder, windows_only) in wrappers::project_folders(&key, &unit) {
            split.project_file(&folder, unit.program.text(), unit.shell, windows_only);
        }
        if let Some(reason) = wrappers::bundle_note(&key, &unit) {
            split.problem(Rule::Unknown, reason, Some(unit.program.text()));
        }
        // The command `npm_config_call` sets runs once for each `npx`: its
        // readings are bounded as a line's own text is.
        if let Launch::Script(_, script, _) = &launched {
            if runs_variable(&key, &unit, script) && !unit::read_from_variable(split, script.text())
            {
                split.push(unit);
                return;
            }
        }
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
        let elsewhere = matches!(launched, Launch::Elsewhere(..));
        match launched {
            // The wrapper starts what it runs in a folder of its own, and
            // takes no more of the wrappers left for that.
            Launch::In(folder, shell, inner) => {
                split.start_in(&folder, shell.unwrap_or(unit.shell));
                add_launched(split, unit, depth, wrappers - used, Some(*inner));
                return;
            }
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
                // Each reading starts where the line is: a folder the first
                // starts its program in is not the second's.
                let folders = split.folders_mark();
                add_launched(split, unit.clone(), depth, left, Some(*first));
                split.leave_folders(folders);
                add_launched(split, unit, depth, left, Some(*second));
                return;
            }
            Launch::Itself => {
                // `coproc NAME {` with the group's commands on the lines
                // after it runs nothing of its own: what runs is read there,
                // and the `}` that closes the group is taken off by the walk.
                if key == "coproc" && unit.shell == Shell::Posix && unit.wrappers.is_empty() {
                    if let Some(groups) = coproc_opens_only(&unit.args) {
                        split.open_groups += groups;
                        return;
                    }
                }
                // `repeat 3 {` and `repeat 3 do` with the body on the lines
                // after them, and `repeat 3` with its body the statement
                // after it.
                if key == "repeat" && unit.shell == Shell::Posix {
                    if let Some((groups, opens_do)) = repeat_opens_only(&unit.args) {
                        split.begin_repeat(opens_do, false);
                        split.open_groups += groups;
                        return;
                    }
                    split.repeat_alone |= unit.args.len() == 1;
                }
                // What `find` picks is handed to the programs its `-exec` runs.
                let first = split.units.len();
                if key == "find" && unit.shell == Shell::Posix {
                    find_exec(split, &unit, depth);
                }
                let execs = first..split.units.len();
                // `NODE_OPTIONS='--require ./x.js' npm test`: every node the
                // program starts loads the module first, code the line does
                // not show. A builtin that starts nothing starts no node.
                if !STARTS_NOTHING.contains(&key.as_str()) {
                    if let Some(value) = split.node_options.preload() {
                        let value = value.text().to_string();
                        split.problem(
                            Rule::Unknown,
                            "loads code through NODE_OPTIONS that the guard does not read",
                            Some(&value),
                        );
                    }
                }
                let at = split.units.len();
                split.push(unit);
                split.nest(execs, at..at + 1);
                return;
            }
            Launch::Runs(start) => {
                unit = runs_after(split, unit, key, start, depth);
            }
            Launch::Input { start, replace } => {
                unit = runs_from_input(split, unit, key, start, replace);
            }
            Launch::Replace(replacement) => {
                // A package runner puts a venv or `node_modules/.bin` on
                // `PATH`, passes npm's config on as environment variables
                // and loads `--env-file`; `bun run` loads `.env`. What it
                // starts has an environment the line does not show.
                split.environment += 1;
                // `Start-Process -RedirectStandardInput f` feeds the program
                // it starts the file, which is the next unit.
                if key == "start-process" {
                    if let Some(file) = wrappers::standard_input(&unit) {
                        let at = split.units.len();
                        split.redirect(at..at + 1, file, true);
                    }
                }
                unit = *replacement;
            }
            Launch::Script(shell, script, source) | Launch::Elsewhere(shell, script, source) => {
                add_script(split, unit, &key, shell, (script, source), elsewhere, depth);
                return;
            }
            Launch::Commands {
                shell,
                commands,
                moves,
            } => {
                // `split --filter` hands each piece of its file to the
                // command's input.
                let input = (key == "split")
                    .then(|| split_input(&key, &unit.args))
                    .flatten();
                let start = split.units.len() + 1;
                run_commands(split, unit, shell, commands, moves, depth);
                if let Some(file) = input {
                    let end = split.units.len();
                    if start < end {
                        split.redirect(start..end, file, true);
                    }
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
                let at = split.units.len();
                split.push(unit);
                inline::apply_all(split, at, language, &code, depth + 1);
                split.launch_done();
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
                split.problem(Rule::RunDownloaded, Said::downloaded_script(), None);
                split.push(unit);
                return;
            }
            Launch::Unread(script) => {
                unread_script(split, &script);
                split.push(unit);
                return;
            }
            // `python3 < <(curl -s https://x)`: the code it reads is a
            // download, as `python3 <(curl -s https://x)` runs one.
            Launch::Reads(_)
                if unit
                    .stdin
                    .as_ref()
                    .is_some_and(|input| input.text() == crate::posix::DOWNLOADED_INPUT) =>
            {
                split.problem(Rule::RunDownloaded, Said::downloaded_script(), None);
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

/// What `unit`, a wrapper `key` that runs the program at `start` with the
/// arguments after it (`sudo rm -rf x`, `env X=1 cmd`), runs, after noting
/// what it hands that program. A function of its own, so that what it holds
/// is not on the stack of [`add_launched`] in the deepest walk of a nested
/// line.
#[inline(never)]
fn runs_after(split: &mut Split, mut unit: Unit, key: String, start: usize, depth: usize) -> Unit {
    note_wrapper(split, &key, &unit, start);
    let own = unit.args.get(..start).unwrap_or_default();
    // `coproc { … }`, `time { … }`, `! { … }`, `repeat 3 { … }`: the `}`
    // that closes the group is a command of its own to the grammar, and
    // runs nothing.
    // So is the `done` that closes the list of a `do` the walk read as a
    // `repeat`'s (`repeat 3; do { …; }; done`).
    if unit.shell == Shell::Posix && (key == "coproc" || key == "do" || starts_command(&key)) {
        // zsh's `repeat N` runs what comes after its count again and again:
        // a loop whose body the grammar does not see. Its body is a group
        // or a list after `do` when one follows the count, or else the
        // chain of `&&`, `||` and `|` the command after it starts.
        if key == "repeat" {
            let after = own.get(1).and_then(Arg::known);
            split.begin_repeat(
                after == Some("do"),
                !after.is_some_and(|word| word == "do" || opens_group(word)),
            );
        }
        let program = if opens_group(&key) {
            key.matches('{').count()
        } else {
            0
        };
        split.open_groups += program + coproc_groups(own);
    }
    split.environment += usize::from(sets_environment(&key, own));
    split
        .node_options
        .extend(wrappers::node_options(&unit.args, start));
    split
        .python_path
        .extend(wrappers::python_path(&unit.args, start));
    for (name, value) in wrappers::zip_env(&unit.args, start) {
        split.zip_env.set(name, &value, false);
    }
    for (name, value) in wrappers::tf_cli_args(&unit.args, start) {
        split.note_argument_variable(name, value);
    }
    // `env BASH_ENV=f bash`: the shell it starts runs `f`.
    let files = if key == "env" && unit.shell == Shell::Posix {
        startup::env(split, &unit.args[..start], depth)
    } else {
        Vec::new()
    };
    let multi_call = MULTI_CALL.contains(&key.as_str());
    unit = inner(unit, key, start, &Hands::Nothing);
    if multi_call {
        applet(&mut unit);
    }
    for file in files {
        if !startup::push(&mut unit.startup, file) {
            split.startup_overflow();
        }
    }
    unit
}

/// What `unit`, a wrapper `key` that runs the program at `start` with what
/// it reads on its input (`xargs rm`), runs, after noting what it hands
/// that program; `replace` is the word it puts each item in place of. A
/// function of its own, as [`runs_after`] is.
#[inline(never)]
fn runs_from_input(
    split: &mut Split,
    mut unit: Unit,
    key: String,
    start: usize,
    replace: Option<String>,
) -> Unit {
    note_wrapper(split, &key, &unit, start);
    // `xargs -a FILE cmd`: the program's arguments are what the
    // file holds, as if it were redirected onto its input.
    if key == "xargs" {
        if let Some(file) = wrappers::arg_file(unit.args.get(..start).unwrap_or_default()) {
            let at = split.units.len();
            split.read(unit.shell, file.clone());
            split.redirect(at..at + 1, file, true);
        }
    }
    let own = unit.args.get(..start).unwrap_or_default();
    split.environment += usize::from(sets_environment(&key, own));
    split
        .node_options
        .extend(wrappers::node_options(&unit.args, start));
    split
        .python_path
        .extend(wrappers::python_path(&unit.args, start));
    for (name, value) in wrappers::zip_env(&unit.args, start) {
        split.zip_env.set(name, &value, false);
    }
    for (name, value) in wrappers::tf_cli_args(&unit.args, start) {
        split.note_argument_variable(name, value);
    }
    let hands = replace.map_or(Hands::After, Hands::Where);
    unit = inner(unit, key, start, &hands);
    unit
}

/// Add `unit`, a program that runs `script` in `shell` (`bash -c '…'`,
/// `eval '…'`, `trap '…' EXIT`, `alias x='…'`), and what the script runs.
/// `elsewhere` says it runs it in a folder the line does not name (`git
/// submodule foreach`). A function of its own, so that what it holds is not
/// on the stack of [`add_launched`] in the deepest walk of a nested line.
#[inline(never)]
fn add_script(
    split: &mut Split,
    unit: Unit,
    key: &str,
    shell: Shell,
    (script, source_of): (Arg, Source),
    elsewhere: bool,
    depth: usize,
) {
    // A shell started with the option on (`bash -O dotglob -c`,
    // `zsh -o globdots -c`) runs its script with it on.
    let starts_hidden = is_shell(key) && shell == Shell::Posix && dotglob::starts_with(&unit.args);
    // And `zsh -o extendedglob -c` with zsh's extended patterns.
    let starts_extended = is_shell(key)
        && shell == Shell::Posix
        && extended::starts_with(extended::EXTENDED_GLOB, &unit.args);
    // And `zsh -o autocd -c` with a command of one word run as a
    // `cd` to it.
    let starts_autocd = is_shell(key)
        && shell == Shell::Posix
        && extended::starts_with(extended::AUTO_CD, &unit.args);
    let stage = unit.stage;
    // A shell handed a file or a pipe on its input hands it on
    // to what its script runs (`cmd /c python < x.py`).
    let hands_input = key != "trap" && fed(&unit);
    let inherited = key == "trap" && trap_inherited(&unit.args);
    // A script `xargs` or `parallel` hands to a shell runs once
    // for each item it reads, as a loop body runs: its `$1` and
    // `$@` are a different value each time, only known when it
    // runs.
    let per_item = key == "parallel"
        || unit
            .wrappers
            .iter()
            .any(|wrapper| matches!(wrapper.as_str(), "xargs" | "parallel"));
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
            ..
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
            // `autocd` too, which an `eval`, a `trap` or an
            // alias turns on for the line, as each runs in
            // this shell.
            let outer_autocd = split.autocd;
            if starts_autocd {
                split.turn_autocd_on();
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
            split.inherits_input += usize::from(hands_input);
            split.repeats += usize::from(per_item);
            // `git submodule foreach` runs its command in a folder
            // the line does not name; the rest of the line is
            // where it was.
            let outer_dir = elsewhere.then(|| split.dir_snapshot());
            if elsewhere {
                split.move_unknown("the folder it runs in");
            }
            if key == "alias" {
                define_aliases(split, shell_at, shell, depth);
            } else {
                split.launch(shell_at, source_of);
                unit::script_in(split, &text, shell, depth + 1, here);
                split.launch_done();
            }
            if let Some(place) = outer_dir {
                split.restore_dir(place);
            }
            split.repeats -= usize::from(per_item);
            split.inherits_input -= usize::from(hands_input);
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
            if !matches!(key, "eval" | "trap" | "alias") {
                split.autocd = outer_autocd;
            }
            if !matches!(key, "eval" | "trap") {
                split.restore_hidden(outer);
            } else if stage.is_some() {
                split.restore_hidden(outer.or(split.hidden_snapshot()));
            }
        }
        other => unread_script(split, &other),
    }
}

/// An alias's name and value, and the argument of the `alias` the value is
/// in, with where in it the value starts.
type Definition = (String, String, Option<(usize, usize)>);

/// Read each `NAME=VALUE` of the `alias` at `shell_at` as a body of its
/// own. A use of the name runs the value in this shell, where the line is
/// then, as a call runs a function's body: it is read as one (see
/// [`Split::end_body`]), and its `cd` moves the line. A function of its own,
/// so that what it holds is not on the stack of [`add_launched`] in the
/// deepest walk of a nested line.
#[inline(never)]
fn define_aliases(split: &mut Split, shell_at: usize, shell: Shell, depth: usize) {
    // Each name and value, and where the value is: the argument it is a
    // part of, by where it is in memory, and from where in it.
    let definitions: Vec<Definition> = split
        .units
        .get(shell_at)
        .map(|alias| {
            aliases(&alias.args)
                .into_iter()
                .map(|(name, value)| {
                    let within = alias.args.iter().enumerate().find_map(|(at, arg)| {
                        let word = arg.known()?;
                        let offset =
                            (value.as_ptr() as usize).checked_sub(word.as_ptr() as usize)?;
                        (offset + value.len() <= word.len()).then_some((at, offset))
                    });
                    (name.to_string(), value.to_string(), within)
                })
                .collect()
        })
        .unwrap_or_default();
    for (name, value, within) in definitions {
        // One the line surely runs, in this shell, takes the place of those
        // before it.
        let replaces = split.branches == 0 && split.repeats == 0 && split.apart == 0;
        let first = split.units.len();
        split.branches += 1;
        split.bodies += 1;
        split.repeats += 1;
        split.begin_body();
        split.last_read = 0..0;
        if let Some((at, offset)) = within {
            split.launch_at(shell_at, at, offset);
        }
        unit::script_in(split, &value, shell, depth + 1, true);
        split.launch_done();
        let command = std::mem::take(&mut split.last_read);
        split.alias_command(&name, command, replaces);
        split.end_body(Some(&name));
        split.repeats -= 1;
        split.bodies -= 1;
        split.branches -= 1;
        split.alias_body(&name, first..split.units.len());
    }
}

/// The words in front of a command after which zsh and bash still expand
/// an alias in its place: `time` (and `!`, which is no wrapper), and zsh's
/// `nocorrect`. Behind any other (`sudo x`, `env x`, `command x`,
/// `builtin x`, `noglob x`) the name is a program's.
fn expands_alias(wrappers: &[String]) -> bool {
    wrappers
        .iter()
        .all(|wrapper| matches!(wrapper.as_str(), "time" | "nocorrect"))
}

/// The most commands one use of an alias is read as, through the aliases
/// its value's last command names in turn.
const MAX_ALIAS_READINGS: usize = 16;

/// What a use of an alias the line defines runs when it has words of its
/// own, as the shell expands it: the last command of the alias's value with
/// the use's words after its own (`alias x='rm -rf'; x /etc` runs `rm -rf
/// /etc`, `alias x='env '; x rm -rf /etc` runs `env rm -rf /etc`), one for
/// each value the alias may have. When that command names an alias in turn
/// it is expanded too, but never an alias the expansion has already gone
/// through (`alias rm='rm -i'; rm -rf build` runs `rm -i -rf build`).
/// `None` when `unit` is no such use. A use without words runs the value as
/// it is, which is read where the alias is defined, and placed from where
/// the use is made (see [`Split::alias_body`]).
#[inline(never)]
fn alias_readings(split: &mut Split, unit: &Unit) -> Option<Vec<Unit>> {
    if unit.shell != Shell::Posix || unit.args.is_empty() || !expands_alias(&unit.wrappers) {
        return None;
    }
    split.alias_commands(unit.program.known()?)?;
    let mut readings = Vec::new();
    let mut todo = vec![(unit.clone(), Vec::<String>::new())];
    while let Some((mut current, mut seen)) = todo.pop() {
        let name = current
            .program
            .known()
            .filter(|name| {
                expands_alias(&current.wrappers) && !seen.iter().any(|seen| seen == name)
            })
            .map(str::to_string);
        let commands = name
            .as_deref()
            .and_then(|name| split.alias_commands(name))
            .map(|commands| match commands {
                unit::AliasCommands::Known(known) => Some(known.to_vec()),
                unit::AliasCommands::Unread => None,
            });
        let (Some(name), Some(commands)) = (name, commands) else {
            current.aliased = true;
            readings.push(current);
            continue;
        };
        let Some(commands) = commands else {
            split.problem(
                Rule::Unknown,
                "runs an alias the line defines more times than the guard reads",
                Some(&name),
            );
            current.aliased = true;
            readings.push(current);
            continue;
        };
        if commands.is_empty() {
            current.aliased = true;
            readings.push(current);
            continue;
        }
        seen.push(name);
        for at in commands {
            let Some(last) = split.units.get(at) else {
                continue;
            };
            split.alias_words += last.args.len();
            if split.alias_words > unit::MAX_ALIAS_WORDS
                || readings.len() + todo.len() >= MAX_ALIAS_READINGS
            {
                split.problem(
                    Rule::Unreadable,
                    "uses aliases in more ways than the guard reads",
                    unit.program.known(),
                );
                current.aliased = true;
                readings.push(current);
                return Some(readings);
            }
            todo.push((joined(&current, last), seen.clone()));
        }
    }
    Some(readings)
}

/// `last`, the last command of an alias's value, with the words of `used`, a
/// use of the alias, after its own, run where the use is.
#[inline(never)]
fn joined(used: &Unit, last: &Unit) -> Unit {
    let mut unit = used.clone();
    unit.program = last.program.clone();
    unit.args = last.args.iter().chain(&used.args).cloned().collect();
    unit.wrappers.extend(last.wrappers.iter().cloned());
    unit
}

/// When `unit` is a use of an alias with words of its own, add it and the
/// readings of what it runs (see [`alias_readings`]): the use itself, by its
/// name, is a call of the alias's value, placed where it is made; each
/// reading is judged as a command written there, with at most `wrappers`
/// more to come off. One reading takes the place of `unit`, which
/// [`add_launched`] goes on with (`false`); each of two or more may be the
/// one that runs, so each is read as a branch, and all are added (`true`).
/// A function of its own, so that what it holds is not on the stack of
/// [`add_launched`] in the deepest walk of a nested line.
#[inline(never)]
fn add_aliased(split: &mut Split, unit: &mut Unit, depth: usize, wrappers: usize) -> bool {
    let Some(mut readings) = alias_readings(split, unit) else {
        return false;
    };
    split.push(unit.clone());
    if readings.len() < 2 {
        if let Some(only) = readings.pop() {
            *unit = only;
        }
        return false;
    }
    let program = unit.program.text().to_string();
    split.branches += 1;
    for (index, reading) in readings.into_iter().enumerate() {
        if index > 0 && !split.fork(MAX_FORKS) {
            split.problem(
                Rule::Unreadable,
                "reads in too many ways to judge each",
                Some(&program),
            );
            break;
        }
        add_launched(split, reading, depth, wrappers, None);
    }
    split.branches -= 1;
    true
}

/// Add what a wrapper writes its own output to (see [`tools::outputs`]): a
/// file is written as a redirect writes it, from where the wrapper runs, and
/// a command it pipes the output to is a script of its own for a POSIX
/// shell.
fn output_of(split: &mut Split, unit: &Unit, output: tools::Output, depth: usize) {
    let shell = unit.shell;
    match output {
        tools::Output::File(file) => split.write(shell, file),
        tools::Output::Command(Arg::Known(command)) => {
            // Placed at the command: what it pipes to is no argument of
            // its own.
            split.launch_done();
            unit::script_in(split, &command, Shell::Posix, depth + 1, false);
        }
        tools::Output::Command(command) => split.problem(
            Rule::Unknown,
            "pipes its output to a command only known when it runs",
            Some(command.text()),
        ),
    }
}

/// A script only known when it runs: a download when it is a process
/// substitution that downloads (`bash <(curl …)`), and not read otherwise.
fn unread_script(split: &mut Split, script: &Arg) {
    if split.downloads.contains(script.text()) {
        split.problem(Rule::RunDownloaded, Said::downloaded_script(), None);
    } else {
        split.problem(
            Rule::Unknown,
            "runs a script only known when it runs",
            Some(script.text()),
        );
    }
}

/// Add `unit`, an archiver, and the `commands` it runs through `shell`
/// besides, each nested under it, from a folder only known when it runs
/// when it `moves`. A function of its own, so that its locals are not on
/// the stack of [`add_launched`] in the deepest walk of a nested line.
#[inline(never)]
fn run_commands(
    split: &mut Split,
    unit: Unit,
    shell: Shell,
    commands: Vec<Arg>,
    moves: bool,
    depth: usize,
) {
    let at = split.units.len();
    split.push(unit);
    for command in commands {
        let Arg::Known(text) = command else {
            split.problem(
                Rule::Unknown,
                "runs a command only known when it runs",
                Some(command.text()),
            );
            continue;
        };
        // Each runs in a shell of its own, which a `GLOBIGNORE` in front of
        // the program hands the option to.
        let outer = split.hidden_snapshot();
        if split.scoped_hidden() {
            split.hide_for_script();
        }
        // `tar -C dir` runs it from `dir`, or from where the line was:
        // which, only the order of the run shows.
        let outer_dir = moves.then(|| split.dir_snapshot());
        if moves {
            split.move_unknown("the folder it runs in");
        }
        let first = split.units.len();
        // Placed at the command: the archiver's arguments say what it
        // runs, not where in them it is.
        split.launch_done();
        unit::script_in(split, &text, shell, depth + 1, false);
        if let Some(place) = outer_dir {
            split.restore_dir(place);
        }
        split.nest(at..at + 1, first..split.units.len());
        split.restore_hidden(outer);
    }
}

/// The letters and the names of the options of `split` (GNU's and BSD's)
/// and of `csplit` that take a value.
const SPLIT_SHORT: &str = "abClntp";
const SPLIT_LONG: [&str; 8] = [
    "suffix-length",
    "bytes",
    "line-bytes",
    "lines",
    "number",
    "separator",
    "additional-suffix",
    "filter",
];
/// Every long option of `split`, for the prefixes of their names.
const SPLIT_ALL: [&str; 15] = [
    "suffix-length",
    "bytes",
    "line-bytes",
    "lines",
    "number",
    "separator",
    "additional-suffix",
    "filter",
    "elide-empty-files",
    "numeric-suffixes",
    "hex-suffixes",
    "unbuffered",
    "verbose",
    "help",
    "version",
];
const CSPLIT_SHORT: &str = "bfn";
const CSPLIT_LONG: [&str; 3] = ["suffix-format", "prefix", "digits"];
const CSPLIT_ALL: [&str; 10] = [
    "suffix-format",
    "prefix",
    "digits",
    "keep-files",
    "quiet",
    "silent",
    "elide-empty-files",
    "suppress-matched",
    "help",
    "version",
];

/// The operands of `split` or `csplit`, past its options as `getopt` reads
/// them (`split -db 100 FILE`, `csplit -sf PREFIX FILE`).
fn pieces_operands<'a>(key: &str, args: &'a [Arg]) -> Vec<&'a Arg> {
    if key == "csplit" {
        unit::operands_clustered(args, CSPLIT_SHORT, &CSPLIT_LONG, &CSPLIT_ALL)
    } else {
        unit::operands_clustered(args, SPLIT_SHORT, &SPLIT_LONG, &SPLIT_ALL)
    }
}

/// The file `split` or `csplit` reads: its first operand, or its input for
/// none or `-`.
pub(crate) fn split_input(key: &str, args: &[Arg]) -> Option<Arg> {
    pieces_operands(key, args)
        .first()
        .filter(|file| file.known() != Some("-"))
        .map(|file| (*file).clone())
}

/// The most names of pieces the guard judges for one command.
const MOST_PIECES: usize = 32;

/// The values of an option of `split` or `csplit`, by its letter and its
/// long name, which may be written by any prefix of it that no other long
/// option starts with, attached after `=` or as the next word.
fn piece_option(key: &str, args: &[Arg], short: &str, long: &str) -> Vec<Arg> {
    let (all, valued) = if key == "csplit" {
        (&CSPLIT_ALL[..], CSPLIT_SHORT)
    } else {
        (&SPLIT_ALL[..], SPLIT_SHORT)
    };
    let mut found = unit::option_values(args, short, &[], valued);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let Some(name) = text.strip_prefix("--") else {
            continue;
        };
        let (name, value) = name
            .split_once('=')
            .map_or((name, None), |(name, value)| (name, Some(value)));
        if unit::long_named(name, all) == Some(long) {
            match value {
                Some(value) => found.push(Arg::Known(value.to_string())),
                None => found.extend(iter.next().cloned()),
            }
        }
    }
    found
}

/// The names `csplit` gives the suffix of its pieces by `format`, a `printf`
/// format of one integer conversion (`%02d.txt`, `c%.0d`): for the numbers
/// of the first pieces, and the pattern of every name it makes
/// (`chap*.md`). `None` for a format that is not one of those.
fn formatted_suffixes(format: &str) -> Option<(Vec<String>, String)> {
    let at = {
        let mut chars = format.char_indices();
        loop {
            let (at, c) = chars.next()?;
            if c == '%' {
                if format[at + 1..].starts_with('%') {
                    chars.next();
                    continue;
                }
                break at;
            }
        }
    };
    let (before, spec) = format.split_at(at);
    let spec = &spec[1..];
    let flags_end = spec
        .find(|c: char| !"-+ #0'".contains(c))
        .unwrap_or(spec.len());
    let (flags, spec) = spec.split_at(flags_end);
    let width_end = spec
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(spec.len());
    let (width, spec) = spec.split_at(width_end);
    let (precision, spec) = match spec.strip_prefix('.') {
        Some(rest) => {
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            (
                Some(rest[..end].parse::<usize>().unwrap_or(0)),
                &rest[end..],
            )
        }
        None => (None, spec),
    };
    let conversion = spec.chars().next()?;
    let after = &spec[conversion.len_utf8()..];
    if !"diuoxX".contains(conversion) || after.replace("%%", "").contains('%') {
        return None;
    }
    let width = width.parse::<usize>().unwrap_or(0).min(64);
    let literal = |text: &str| text.replace("%%", "%");
    let names = (0..MOST_PIECES)
        .map(|number| {
            let mut digits = match conversion {
                'o' => format!("{number:o}"),
                'x' => format!("{number:x}"),
                'X' => format!("{number:X}"),
                _ => number.to_string(),
            };
            if let Some(precision) = precision {
                if precision == 0 && number == 0 {
                    digits.clear();
                }
                while digits.len() < precision.min(64) {
                    digits.insert(0, '0');
                }
            }
            if flags.contains('#') && number != 0 {
                match conversion {
                    'x' => digits.insert_str(0, "0x"),
                    'X' => digits.insert_str(0, "0X"),
                    'o' => digits.insert(0, '0'),
                    _ => {}
                }
            }
            if flags.contains('+') && "di".contains(conversion) {
                digits.insert(0, '+');
            }
            while digits.len() < width {
                if flags.contains('-') {
                    digits.push(' ');
                } else if flags.contains('0') && precision.is_none() {
                    digits.insert(0, '0');
                } else {
                    digits.insert(0, ' ');
                }
            }
            format!("{}{digits}{}", literal(before), literal(after))
        })
        .collect();
    Some((names, format!("{}*{}", literal(before), literal(after))))
}

/// What the options `-d`, `-x`, `--numeric-suffixes` and `--hex-suffixes` of
/// `split` have said so far of the names of its pieces.
#[derive(Default)]
struct Numbering<'a> {
    /// The names are numbers or hex digits.
    numbered: bool,
    /// They are hex digits.
    hex: bool,
    /// Where they start, as the last option that said so wrote it.
    from: Option<&'a str>,
    /// A FROM was not digits the option allowed.
    refused: bool,
}

impl<'a> Numbering<'a> {
    fn set(&mut self, hex: bool, value: Option<&'a str>) {
        self.numbered = true;
        self.hex = hex;
        if let Some(text) = value {
            self.refused |= !Self::digits(text, hex);
            self.from = Some(text);
        }
    }

    /// Whether `text` is a number in digits, or in lower case hex digits.
    fn digits(text: &str, hex: bool) -> bool {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_digit() || (hex && matches!(c, 'a'..='f')))
    }
}

/// The suffixes `split` or `csplit` gives its pieces, in order: letters, or
/// digits for `-d` and for `csplit` (hex for `-x`), as many as `-a` (`-n` of
/// `csplit`) says, two without it, and `split`'s `--additional-suffix` after
/// it. The pieces a `-n N` makes, or every suffix when there are few, as far
/// as [`MOST_PIECES`]; otherwise only the first. Also whether those are every
/// suffix there can be, how long a suffix is, and what ends each name. `None`
/// when the pieces go to the output (`split -n K/N`).
fn piece_suffixes(key: &str, args: &[Arg]) -> Option<(Vec<String>, bool, usize, String)> {
    let csplit = key == "csplit";
    let (short, long, valued) = if csplit {
        ("n", "digits", CSPLIT_SHORT)
    } else {
        ("a", "suffix-length", SPLIT_SHORT)
    };
    let length = piece_option(key, args, short, long)
        .pop()
        .and_then(|text| text.known()?.parse::<u32>().ok())
        .unwrap_or(2)
        .clamp(1, 8);
    // GNU `split` reads `-d`, `-x`, `--numeric-suffixes[=FROM]` and
    // `--hex-suffixes[=FROM]` in order: each says whether the names are
    // numbers or hex digits, and one with a FROM says where they start, which
    // it checks against the digits it allows then. One without a FROM leaves
    // the FROM an earlier option gave.
    let mut numbering = Numbering::default();
    for text in args.iter().filter_map(Arg::known) {
        if text == "--" {
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            match unit::long_named(name, &SPLIT_ALL) {
                Some("numeric-suffixes") => numbering.set(false, value),
                Some("hex-suffixes") => numbering.set(true, value),
                _ => {}
            }
        } else if text.len() > 1 && text.starts_with('-') {
            for letter in text[1..].chars().take_while(|c| !valued.contains(*c)) {
                match letter {
                    'd' => numbering.set(false, None),
                    'x' => numbering.set(true, None),
                    _ => {}
                }
            }
        }
    }
    // A FROM refused when it was given writes no piece.
    if numbering.refused {
        return None;
    }
    let (hex, from) = (numbering.hex, numbering.from);
    let numbered = csplit || numbering.numbered;
    let alphabet: Vec<char> = if csplit || (numbered && !hex) {
        ('0'..='9').collect()
    } else if numbered {
        ('0'..='9').chain('a'..='f').collect()
    } else {
        ('a'..='z').collect()
    };
    let radix = alphabet.len();
    let room = radix.checked_pow(length).unwrap_or(usize::MAX);
    let width = usize::try_from(length).unwrap_or(2);
    let extra = (!csplit)
        .then(|| piece_option(key, args, "", "additional-suffix").pop())
        .flatten()
        .and_then(|text| text.known().map(str::to_string))
        .unwrap_or_default();
    // FROM is a number the program reads, and refuses past what the names
    // hold: no piece is then written. One given in digits that a later option
    // does not allow (`--hex-suffixes=c -d`) is used as it is written, and
    // the names after it are any the pattern matches.
    let start = match from {
        None => 0,
        Some(text) if !Numbering::digits(text, hex) => {
            return Some((Vec::new(), false, width, extra));
        }
        Some(text) => match usize::from_str_radix(text, u32::try_from(radix).unwrap_or(10)) {
            Ok(start) if start < room => start,
            _ => return None,
        },
    };
    // `-n N` and `-n l/N`, `-n r/N`: N pieces; `-n K/N` and `-n l/K/N` write
    // one of them to the output, and no file.
    let mut count = None;
    if !csplit {
        if let Some(text) = piece_option(key, args, "n", "number").pop() {
            if let Some(text) = text.known() {
                let number = text
                    .strip_prefix("l/")
                    .or_else(|| text.strip_prefix("r/"))
                    .unwrap_or(text);
                if number.contains('/') {
                    return None;
                }
                count = number.parse::<usize>().ok();
            }
        }
    }
    let wanted = match count {
        Some(count) => count.min(room.saturating_sub(start)),
        None if room <= MOST_PIECES => room.saturating_sub(start),
        None => 1,
    };
    let complete = wanted <= MOST_PIECES && (count.is_some() || room <= MOST_PIECES);
    let wanted = wanted.clamp(1, MOST_PIECES);
    let suffixes = (0..wanted)
        .map(|at| {
            let mut at = start.saturating_add(at);
            let mut name = vec![alphabet[0]; width];
            for place in name.iter_mut().rev() {
                *place = alphabet[at % radix];
                at /= radix;
            }
            format!("{}{extra}", name.into_iter().collect::<String>())
        })
        .collect();
    Some((suffixes, complete, width, extra))
}

/// The most pieces `csplit` makes from its patterns: one more than the
/// patterns, and a count after one (`{N}`) repeats it N times more; `None`
/// when one repeats as often as it can (`{*}`).
fn csplit_pieces(args: &[Arg]) -> Option<usize> {
    let mut pieces: usize = 1;
    for pattern in pieces_operands("csplit", args).into_iter().skip(1) {
        let text = pattern.known()?;
        match text
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            Some("*") => return None,
            Some(count) => pieces = pieces.checked_add(count.parse::<usize>().ok()?)?,
            None => pieces += 1,
        }
    }
    Some(pieces)
}

/// What the pieces of `split` (its prefix, `x` without one) or `csplit`
/// (`-f`'s, `xx` without one) are named, each as a path: the prefix and a
/// suffix, a name in the folder the line is in. A prefix only known when it
/// runs makes the name so. None when no piece is written to a file.
pub(crate) fn pieces_names(key: &str, args: &[Arg]) -> Vec<Arg> {
    let prefix = if key == "csplit" {
        piece_option(key, args, "f", "prefix")
            .pop()
            .unwrap_or_else(|| Arg::Known("xx".to_string()))
    } else {
        pieces_operands(key, args)
            .get(1)
            .map_or_else(|| Arg::Known("x".to_string()), |prefix| (*prefix).clone())
    };
    let Some(prefix) = prefix.known() else {
        return vec![prefix];
    };
    // A format `csplit` is given for the suffix: the names it makes, or only
    // known when it runs for one that is not a simple integer.
    if key == "csplit" {
        if let Some(format) = piece_option(key, args, "b", "suffix-format").pop() {
            let unknown = Arg::Unknown(format!("{prefix}${{SPLIT_PIECE_SUFFIX}}"));
            return match format.known().and_then(formatted_suffixes) {
                Some((suffixes, pattern)) => {
                    let mut names: Vec<Arg> = suffixes
                        .into_iter()
                        .map(|suffix| Arg::Known(format!("{prefix}{suffix}")))
                        .collect();
                    // Past the names judged, more pieces are named as the
                    // format makes them: any name its pattern matches.
                    if csplit_pieces(args).is_none_or(|pieces| pieces > MOST_PIECES) {
                        names.push(Arg::Known(format!("{prefix}{pattern}")));
                    }
                    names
                }
                None => vec![unknown],
            };
        }
    }
    let Some((suffixes, complete, width, extra)) = piece_suffixes(key, args) else {
        return Vec::new();
    };
    let mut names: Vec<Arg> = suffixes
        .into_iter()
        .map(|suffix| Arg::Known(format!("{prefix}{suffix}")))
        .collect();
    // Past the names judged, any file the pattern of a piece's name matches
    // may be one.
    if !complete {
        names.push(Arg::Known(format!("{prefix}{}{extra}", "?".repeat(width))));
    }
    names
}

/// `split --filter=CMD` (`--filter CMD`) runs `CMD` through the shell for
/// each piece of its input, the piece on the command's input, with `$FILE`
/// the piece's name (see [`pieces_names`]): the command is read once for
/// each name. Itself alone without a command.
fn split_filter(args: &[Arg]) -> Launch {
    let mut names = pieces_names("split", args);
    if names.is_empty() {
        names.push(Arg::Unknown(String::new()));
    }
    let mut given = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        // A long option by any unambiguous prefix of its name; one only
        // known when it runs may be the option, and its value a command.
        let text = arg.known().unwrap_or_else(|| arg.text());
        if text == "--" && arg.known().is_some() {
            break;
        }
        let Some(long) = text.strip_prefix("--") else {
            continue;
        };
        let (name, value) = long
            .split_once('=')
            .map_or((long, None), |(name, value)| (name, Some(value)));
        if unit::long_named(name, &SPLIT_ALL) != Some("filter") {
            continue;
        }
        match (value, arg.known()) {
            (Some(value), Some(_)) => given.push(Arg::Known(value.to_string())),
            (Some(value), None) => given.push(Arg::Unknown(value.to_string())),
            (None, _) => given.extend(iter.next().cloned()),
        }
    }
    let mut commands = Vec::new();
    for command in given {
        match command.known() {
            Some(text) if text.contains("$FILE") || text.contains("${FILE}") => {
                for name in &names {
                    // A name only known when it runs is a variable the
                    // command is given that nothing sets.
                    let name = name
                        .known()
                        .filter(|text| {
                            text.chars()
                                .all(|c| c.is_ascii_alphanumeric() || "_./~-+@%,:=?".contains(c))
                        })
                        .map_or_else(|| "${SPLIT_PIECE_NAME}".to_string(), str::to_string);
                    commands.push(Arg::Known(
                        text.replace("${FILE}", &name).replace("$FILE", &name),
                    ));
                }
            }
            _ => commands.push(command),
        }
    }
    if commands.is_empty() {
        Launch::Itself
    } else {
        Launch::Commands {
            shell: Shell::Posix,
            commands,
            moves: false,
        }
    }
}

/// What an archiver that may run commands through a shell besides does:
/// itself alone, or with the commands its arguments give.
#[inline(never)]
fn archiver(key: &str, unit: &Unit) -> Launch {
    let (commands, moves) = crate::detect::archive_commands(key, &unit.args, unit.shell);
    if commands.is_empty() {
        Launch::Itself
    } else {
        Launch::Commands {
            shell: if unit.shell == Shell::Posix {
                Shell::Posix
            } else {
                Shell::Cmd
            },
            commands,
            moves,
        }
    }
}

/// Put the options `ZIPOPT` (or `ZIP`) gives in front of `zip`'s own, as it
/// reads them. A value only known when it runs may hold any option, `-m`
/// among them.
#[inline(never)]
fn zip_options(split: &mut Split, unit: &mut Unit) {
    let read = split.zip_env.read();
    for (reason, text) in read.problems {
        split.problem(Rule::Unknown, reason, text.as_deref());
    }
    let mut words = read.words;
    words.append(&mut unit.args);
    unit.args = words;
}

/// The name and value of each alias `alias NAME=VALUE…` defines: every word
/// that holds one, after a `--` that ends the options.
fn aliases(args: &[Arg]) -> Vec<(&str, &str)> {
    let words = match args.split_first() {
        Some((first, rest)) if first.known() == Some("--") => rest,
        _ => args,
    };
    words
        .iter()
        .filter_map(Arg::known)
        .filter_map(|word| word.split_once('='))
        .filter(|(name, value)| !name.is_empty() && !name.starts_with('-') && !value.is_empty())
        .collect()
}

/// `faketime [OPTIONS] TIME PROGRAM…`: the program after the time it fakes,
/// which may start with a dash (`-15d`). `--date-prog PROG` runs `PROG` as
/// well, to read the time.
fn faketime(args: &[Arg]) -> Launch {
    let start = after_options_by(args, |text, _| match text {
        "--date-prog" => Word::Value,
        "-m" | "-f" | "--exclude-monotonic" | "--disable-shm" => Word::Flag,
        _ => Word::Operand,
    })
    .map(|time| time + 1);
    let program = runs(args, start);
    let date_prog = args
        .iter()
        .position(|arg| arg.known() == Some("--date-prog"))
        .filter(|at| at + 1 < args.len());
    match date_prog {
        Some(at) => Launch::Either(Box::new(program), Box::new(Launch::Runs(at + 1))),
        None => program,
    }
}

/// What a bubblewrap or proot run is read as: the program it starts, judged
/// as written, and unreadable as well, since a bind or another root makes a
/// path it names stand for any folder (`bwrap --bind ~/.ssh /x cat /x/id_rsa`).
fn mapped(program: Launch) -> Launch {
    let unread = Launch::Opaque("runs a command in a file system it maps");
    match program {
        Launch::Itself => unread,
        program => Launch::Either(Box::new(program), Box::new(unread)),
    }
}

/// `bwrap [OPTIONS] PROGRAM…`: its options take none, one, two or three
/// values; past one it does not know, where the program starts is not read.
fn bwrap(args: &[Arg]) -> Launch {
    const ONE: [&str; 33] = [
        "--args",
        "--argv0",
        "--userns",
        "--userns2",
        "--pidns",
        "--uid",
        "--gid",
        "--hostname",
        "--chdir",
        "--unsetenv",
        "--lock-file",
        "--sync-fd",
        "--remount-ro",
        "--overlay-src",
        "--tmp-overlay",
        "--ro-overlay",
        "--exec-label",
        "--file-label",
        "--proc",
        "--dev",
        "--tmpfs",
        "--mqueue",
        "--dir",
        "--seccomp",
        "--add-seccomp-fd",
        "--block-fd",
        "--userns-block-fd",
        "--info-fd",
        "--json-status-fd",
        "--cap-add",
        "--cap-drop",
        "--perms",
        "--size",
    ];
    const TWO: [&str; 14] = [
        "--setenv",
        "--bind",
        "--bind-try",
        "--dev-bind",
        "--dev-bind-try",
        "--ro-bind",
        "--ro-bind-try",
        "--bind-fd",
        "--ro-bind-fd",
        "--file",
        "--bind-data",
        "--ro-bind-data",
        "--symlink",
        "--chmod",
    ];
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            return Launch::Opaque("runs a command in a file system it maps");
        };
        at += match text {
            "--" => return mapped(runs(args, Some(at + 1))),
            _ if !text.starts_with("--") => return mapped(runs(args, Some(at))),
            _ if ONE.contains(&text) => 2,
            _ if TWO.contains(&text) => 3,
            "--overlay" => 4,
            _ if text.starts_with("--unshare-")
                || text.starts_with("--share-")
                || matches!(
                    text,
                    "--disable-userns"
                        | "--assert-userns-disabled"
                        | "--clearenv"
                        | "--new-session"
                        | "--die-with-parent"
                        | "--as-pid-1"
                        | "--level-prefix"
                ) =>
            {
                1
            }
            _ => return Launch::Opaque("runs a command in a file system it maps"),
        };
    }
    mapped(Launch::Itself)
}

/// `proot [OPTIONS] PROGRAM…`: a root (`-r`, `-R`, `-S`) or a bind (`-b`,
/// `-m`) maps the file system the program sees; without one it is the same.
/// `-w DIR` starts the program in `DIR`.
fn proot(args: &[Arg]) -> Launch {
    const VALUES: [&str; 20] = [
        "-r",
        "--rootfs",
        "-b",
        "--bind",
        "-m",
        "--mount",
        "-q",
        "--qemu",
        "-w",
        "--pwd",
        "--cwd",
        "-k",
        "--kernel-release",
        "-i",
        "--change-id",
        "-p",
        "--port",
        "-v",
        "-R",
        "-S",
    ];
    const MAPS: [&str; 8] = [
        "-r", "--rootfs", "-b", "--bind", "-m", "--mount", "-R", "-S",
    ];
    let start = after_options(args, &VALUES);
    let program = started_in(
        args,
        start,
        &["-w", "--pwd", "--cwd"],
        &VALUES,
        runs(args, start),
    );
    let maps = args
        .iter()
        .take(start.unwrap_or(args.len()))
        .filter_map(Arg::known)
        .any(|text| {
            MAPS.iter().any(|map| {
                text == *map
                    || text
                        .strip_prefix(map)
                        .is_some_and(|rest| rest.starts_with('=') || !map.starts_with("--"))
            })
        });
    if maps {
        mapped(program)
    } else {
        program
    }
}

/// The commands `man` is told to run, which it hands to a shell: the pager
/// (`-P CMD`, `-PCMD`, `--pager=CMD`) and the browser (`-HCMD`,
/// `--html=CMD`). Its short options are read as getopt reads them: in a
/// bundle (`-aP CMD`), an option that takes a value takes the rest of the
/// word, or the next word when the rest is empty, and `-H` takes only what is
/// attached. A word only known when it runs may be any of them.
fn man_commands(args: &[Arg]) -> Vec<Arg> {
    /// The short options of man-db that take a value.
    const VALUED: &str = "CRLmMSepPrE";
    let mut commands = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            if arg.text().starts_with('-') {
                commands.push(arg.clone());
            }
            continue;
        };
        if text == "--" {
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            match long.split_once('=') {
                Some(("pager" | "html", value)) => commands.push(Arg::Known(value.to_string())),
                None if long == "pager" => commands.extend(iter.next().cloned()),
                _ => {}
            }
            continue;
        }
        let Some(bundle) = text.strip_prefix('-') else {
            continue;
        };
        for (at, option) in bundle.char_indices() {
            let rest = &bundle[at + option.len_utf8()..];
            if option == 'H' {
                if !rest.is_empty() {
                    commands.push(Arg::Known(rest.to_string()));
                }
                break;
            }
            if VALUED.contains(option) {
                let value = if rest.is_empty() {
                    iter.next().cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
                };
                if option == 'P' {
                    commands.extend(value);
                }
                break;
            }
        }
    }
    commands
}

/// `fzf --preview CMD` runs `CMD` through a shell for each line it shows; a
/// key binding may run any command (`--bind 'enter:execute(…)'`), which is
/// not read.
fn fzf(args: &[Arg]) -> Launch {
    let binds = args.iter().filter_map(Arg::known).any(|text| {
        text == "--bind" || text.starts_with("--bind=") || text.starts_with("--listen")
    });
    if binds {
        return Launch::Opaque("runs the commands its key bindings name");
    }
    option_value(args, "--preview", "--preview").map_or(Launch::Itself, |preview| {
        Launch::Script(Shell::Posix, preview, Source::NONE)
    })
}

/// The first word of an `alias` only known when it runs, after a `--` that
/// ends the options: its name or its value may be anything, so what a call
/// of the alias runs is not read.
fn unread_alias(args: &[Arg]) -> Option<&Arg> {
    let words = match args.split_first() {
        Some((first, rest)) if first.known() == Some("--") => rest,
        _ => args,
    };
    words.iter().find(|word| word.known().is_none())
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
        names,
        place,
        words,
        ..
    } = unit;
    // What is left keeps its words; what the wrapper hands it after them
    // has none.
    let mut words = words.after(start);
    if matches!(hands, Hands::After) {
        words.push(None);
    }
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
        adrift: false,
        rerun: Rc::default(),
        hidden: false,
        startup,
        repeated: false,
        downloaded: false,
        relocates: false,
        followed: false,
        autocd: false,
        aliased: false,
        listings: Vec::new(),
        unread_item: false,
        listed: Vec::new(),
        joined: Vec::new(),
        argument_variables: unit::Noted::default(),
        depth,
        names,
        place,
        words,
        spelled: false,
    }
}

/// `input` is whether the program is handed an input of its own: a pipe, a
/// file, or what the shell whose script runs it was handed (see [`fed`]).
fn launch(key: &str, unit: &Unit, input: bool) -> Launch {
    let args = &unit.args;
    let posix = unit.shell != Shell::Cmd;
    // `rails`, `rake`, `spring rails`, `ruby bin/rails`: what they run, and the
    // template `LOCATION` of the environment names.
    match interpreters::rails_or_rake(key, args) {
        Some(Err(word)) => return Launch::Unread(word.clone()),
        Some(Ok((rails, rest))) => {
            let launch = if rails {
                interpreters::rails(rest)
            } else {
                interpreters::rake(rest)
            };
            // Every value `LOCATION` is given may be the template, the
            // riskiest of them counts (a download, then any other).
            let values = unit.argument_variables.ruby_values();
            let (over, over_other) = unit.argument_variables.ruby_overflow();
            let past = Arg::Unknown("variables set past what is read".to_string());
            let mut template = None;
            for location in values
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("LOCATION"))
                .map(|(_, value)| *value)
                .chain((over || over_other).then_some(&past))
            {
                if let Some(found) = interpreters::template_from(rest, Some(location)) {
                    if matches!(found, Launch::Downloaded) {
                        template = Some(found);
                        break;
                    }
                    template.get_or_insert(found);
                }
            }
            // What the arguments run first, or else the environment's.
            return match (&launch, template) {
                (Launch::Itself | Launch::Reads(_), Some(template)) => template,
                _ => launch,
            };
        }
        None => {}
    }
    match key {
        // `sudo -D DIR` (`--chdir`) starts the command in `DIR`.
        "sudo" => sudo(args),
        "doas" | "pkexec" => runs(args, after_options(args, SUDO_VALUES)),
        "gsudo" => launchers::gsudo(args),
        // systemd's own `sudo`, and a command started as a transient unit.
        "run0" if posix => {
            let start = after_options(args, RUN0_VALUES);
            started_in(
                args,
                start,
                &["-D", "--chdir"],
                RUN0_VALUES,
                runs(args, start),
            )
        }
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
            Launch::Script(Shell::Posix, command, Source::NONE)
        }),
        "su" => option_value(args, "-c", "--command").map_or(Launch::Itself, |script| {
            Launch::Script(Shell::Posix, script, Source::NONE)
        }),
        "env" if posix => env(unit),
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
            let start = after_options_by(args, |text, next| {
                getopt(text, next, &tools::TIME_OPTIONS).0
            });
            match start {
                Some(start) if unit.shell == Shell::Posix => command_after(args, start, false),
                start => runs(args, start),
            }
        }
        // Homebrew's name for GNU `time`, a program and never a shell's
        // word: it runs the program after its options.
        "gtime" if posix => runs(
            args,
            after_options_by(args, |text, next| {
                getopt(text, next, &tools::TIME_OPTIONS).0
            }),
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
        "parallel" if posix => parallel::parallel(args, input),
        // Tracers and runners that run the program after their options.
        "strace" if posix => tools::strace(args),
        "ltrace" if posix => tools::ltrace(args),
        "script" if posix => tools::script(args),
        "ssh-agent" if posix => tools::ssh_agent(args),
        "chronic" if posix => tools::chronic(args),
        "launchctl" if posix => tools::launchctl(unit),
        "lima" if posix => tools::lima(args),
        "limactl" if posix => tools::limactl(args),
        "nix" if posix => nix::nix(unit),
        "nix-shell" if posix => nix::nix_shell(args),
        // GNU parallel's `sem` is `parallel --semaphore`.
        "sem" if posix => parallel::sem(args),
        // Runners that load secrets into the command's environment first.
        "aws-vault" if posix => tools::aws_vault(args),
        "doppler" | "infisical" | "op" => tools::secrets_run(key, unit),
        "direnv" if posix => tools::direnv(args),
        "dotenv" if posix => tools::dotenv(args),
        // `wsl` runs its words in a Linux shell, from any shell of Windows.
        "wsl" => tools::wsl(args),
        // `alias f='cat .env'`: a call of `f` runs the value, read as a
        // script where it is defined, as a function's body is; each
        // `NAME=VALUE` is read apart where the script is.
        // A word only known when it runs (`alias x="$CMD"`) may define any
        // alias with any value, so a later call of it runs a script the
        // guard does not see: the definition is that script. The aliases it
        // defines in full are read as well, so a call of one is judged by
        // what it runs.
        "alias" if unit.shell == Shell::Posix => {
            let known = aliases(args).first().map_or(Launch::Itself, |(_, value)| {
                Launch::Script(Shell::Posix, Arg::Known((*value).to_string()), Source::NONE)
            });
            match (unread_alias(args), known) {
                (Some(word), Launch::Itself) => Launch::Unread(word.clone()),
                (Some(word), known) => {
                    Launch::Either(Box::new(known), Box::new(Launch::Unread(word.clone())))
                }
                (None, known) => known,
            }
        }
        // `busybox rm …` runs its applet: the applet is the program. So
        // does `toybox`.
        "busybox" | "toybox" if posix => runs(args, after_options(args, &[])),
        // `xtables-nft-multi iptables -F` runs the firewall program it names,
        // as busybox runs its applet.
        key if posix && MULTI_CALL.contains(&key) => runs(args, Some(0)),
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
            |script| Launch::Script(Shell::Posix, script, Source::NONE),
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
        // `nsenter -t 1 -a cmd` runs `cmd` in the init process's namespaces.
        "nsenter" if posix => tools::nsenter(args),
        // Sandboxes and fakers that run the program after their options:
        // firejail's options are written with `=`, fakeroot's take a value
        // apart.
        "firejail" if posix => runs(args, after_options(args, &[])),
        "fakeroot" if posix => runs(
            args,
            after_options(args, &["-l", "--lib", "--faked", "-s", "-i", "-b"]),
        ),
        "faketime" if posix => faketime(args),
        // bubblewrap and proot run the program in a file system they map, so
        // a path it names may be any folder of the machine.
        "bwrap" if posix => bwrap(args),
        "proot" if posix => proot(args),
        // `entr cmd` runs `cmd` each time a file changes; `-s` hands its first
        // argument to a shell.
        "entr" if posix => match after_options(args, &[]) {
            Some(start) if has_flag(args, Some('s'), None) => {
                args.get(start).map_or(Launch::Itself, |script| {
                    Launch::Script(Shell::Posix, script.clone(), Source::arg(script))
                })
            }
            start => runs(args, start),
        },
        // `man -P CMD` and fzf's `--preview CMD` hand a command to a shell.
        "man" if posix => man_commands(args)
            .into_iter()
            .map(|command| Launch::Script(Shell::Posix, command, Source::NONE))
            .reduce(|first, second| Launch::Either(Box::new(first), Box::new(second)))
            .unwrap_or(Launch::Itself),
        "fzf" if posix => fzf(args),
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
                Some(start) => Launch::Script(
                    Shell::Posix,
                    join(&args[start..]),
                    Source::joined(&args[start..]),
                ),
                None => Launch::Itself,
            }
        }
        "eval" if unit.shell == Shell::Posix => {
            Launch::Script(Shell::Posix, join(args), Source::joined(args))
        }
        "trap" if unit.shell == Shell::Posix => trap(args),
        "source" | "." if unit.shell == Shell::Posix => match args.first() {
            Some(Arg::Known(script)) if is_stdin(script) => Launch::Reads(Reads::Shell),
            Some(Arg::Known(_)) | None => Launch::Itself,
            Some(script) => Launch::Script(Shell::Posix, script.clone(), Source::arg(script)),
        },
        // Package runners start the program they name.
        "npx" | "npm" | "pnpm" | "pnpx" | "pnx" | "yarn" | "bunx" | "uvx" | "uv" | "pipx" => {
            runner(key, unit)
        }
        // Runners of a project's environment start the command they name,
        // as `uv run` does.
        "poetry" | "pdm" | "hatch" | "conda" | "mamba" | "micromamba" | "pixi" | "rye"
        | "volta" | "mise" | "pipenv" | "bundle" | "bundler" | "rbenv" | "gem" | "asdf" | "rvm"
        | "rvm-exec" | "chruby-exec" => runner(key, unit),
        // `rvm-shell 3.3 -c 'text'` runs the text in a shell.
        "rvm-shell" if posix => wrappers::rvm_shell(args),
        // `corepack pnpm@9 dlx …` starts the package manager it names.
        "corepack" if packages::corepack_runs(args) => {
            Launch::Replace(Box::new(wrappers::running(unit, key, 0)))
        }
        // Packages that run a command: `shx rm`, `cross-env A=1 cmd`.
        "shx" | "cross-env" => packages::command_runner(key, args).unwrap_or(Launch::Itself),
        // Packages that run shell lines: `concurrently 'cmd' 'cmd'`.
        "cross-env-shell" | "concurrently" | "npm-run-all" | "run-s" | "run-p" => {
            packages::line_runner(key, unit).unwrap_or(Launch::Itself)
        }
        "dx" => runner(key, unit),
        // An archiver that runs commands through a shell besides: `/bin/sh`
        // on a POSIX system, and `cmd` on Windows.
        "tar" | "gtar" | "bsdtar" | "zip" => archiver(key, unit),
        "split" if unit.shell == Shell::Posix => split_filter(args),
        "git" => git::launch(args),
        "bun" => bun(unit, input),
        "deno" => deno(unit, input),
        // In every shell: a cmd line starts bash and its kin as the others
        // do (`bash -c "rm -rf /"`).
        key if is_shell(key) => shell(key, args),
        // Also under cmd and PowerShell: the code they are given is not
        // read there, which comes back as `unknown`. A line with nothing to
        // run (`python --version`, a bare `python`) reads its input only
        // where it did before: under any but cmd, and anywhere when
        // something is piped into it or a file is redirected onto it.
        key if is_interpreter(key) => interpreter(key, args, posix, input),
        "cmd" => cmd(args, unit.shell),
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
                Some(script) => {
                    Launch::Script(Shell::PowerShell, (*script).clone(), Source::arg(script))
                }
                None => Launch::Reads(Reads::Shell),
            }
        }
        // An editor handed an input reads its commands, or the keys it is
        // typed, from there.
        key if input && crate::detect::EDITORS.contains(&key) => {
            if crate::detect::editor_reads_input(unit, key) {
                Launch::Reads(Reads::Interpreter)
            } else {
                Launch::Itself
            }
        }
        "start-process" if unit.shell == Shell::PowerShell => start_process(unit),
        "start" if unit.shell == Shell::Cmd => start(args),
        "runas" => match unit::plain(args).last() {
            Some(program) => Launch::Script(Shell::Cmd, (*program).clone(), Source::arg(program)),
            None => Launch::Itself,
        },
        // Windows' console hosts and runners hand the command after their
        // own options on, from any shell of Windows.
        "conhost" => launchers::conhost(args),
        "wt" => launchers::wt(unit),
        "psexec" | "psexec64" | "paexec" => launchers::psexec(args),
        "nircmd" | "nircmdc" => launchers::nircmd(unit, key),
        "pcalua" => launchers::pcalua(args),
        "rundll32" => launchers::rundll32(args),
        "mshta" => launchers::mshta(args),
        // Queues, session and display runners, and the programs that run a
        // command as another user, with other limits or in a toolbox.
        "tsp" if posix => launchers::tsp(args),
        "nq" if posix => launchers::nq(args),
        "dbus-launch" if posix => launchers::dbus_launch(args),
        "dbus-run-session" if posix => launchers::dbus_run_session(args),
        "xvfb-run" if posix => launchers::xvfb_run(args),
        "runuser" if posix => launchers::runuser(args),
        "sg" if posix => launchers::sg(args),
        "setpriv" if posix => launchers::setpriv(args),
        "numactl" if posix => launchers::numactl(args),
        "cgexec" if posix => launchers::cgexec(args),
        "capsh" if posix => launchers::capsh(unit),
        "gosu" | "su-exec" if posix => launchers::as_user(args),
        "chpst" if posix => launchers::chpst(args),
        "setuidgid" | "envuidgid" | "envdir" | "softlimit" | "setlock" | "pgrphack" if posix => {
            launchers::daemontools(key, args)
        }
        "tini" if posix => launchers::tini(args),
        "dumb-init" if posix => launchers::dumb_init(args),
        "flatpak-spawn" if posix => launchers::flatpak_spawn(args),
        "distrobox" | "distrobox-enter" if posix => launchers::distrobox(key, args),
        "toolbox" if posix => launchers::toolbox(args),
        key if posix && launchers::TERMINALS.contains(&key) => launchers::terminal(args),
        "fd" | "fdfind" => named::fd(unit, key),
        _ => Launch::Itself,
    }
}

/// `sudo`: its options, read as `getopt_long` reads them (`-nD DIR`,
/// `--chd DIR`), then the command, which `-D DIR` (`--chdir`) starts in
/// `DIR`.
fn sudo(args: &[Arg]) -> Launch {
    // `sudo -e FILE…` (`--edit`) edits its operands as `sudoedit` does: it
    // runs no command of them.
    if sudo_edits(args).is_some() {
        return Launch::Itself;
    }
    let Some(start) = after_options_by(args, |text, next| getopt(text, next, &SUDO_OPTIONS).0)
        .filter(|start| *start < args.len())
    else {
        return Launch::Itself;
    };
    let own = &args[..start];
    let mut folder = None;
    let mut at = 0;
    while let Some(arg) = own.get(at) {
        at += match arg.known() {
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                let (word, option) = getopt(text, own.get(at + 1), &SUDO_OPTIONS);
                if let Some(("chdir", value)) = option {
                    folder = value;
                }
                if matches!(word, Word::Value) {
                    2
                } else {
                    1
                }
            }
            _ => 1,
        };
    }
    // The `NAME=value` words after its options set the program's
    // environment.
    in_folder(folder, runs(args, Some(after_assignments(args, start))))
}

/// The files `sudo -e` (`--edit`, a bundle holding `e` too) edits, as
/// `sudoedit` edits its operands: every word after its options. `None` when
/// it is not told to edit. Its options are read as `getopt_long` reads them,
/// up to the first operand.
pub(crate) fn sudo_edits(args: &[Arg]) -> Option<&[Arg]> {
    let start = after_options_by(args, |text, next| getopt(text, next, &SUDO_OPTIONS).0)
        .unwrap_or(args.len());
    let own = &args[..start];
    let mut edits = false;
    let mut at = 0;
    while let Some(arg) = own.get(at) {
        at += match arg.known() {
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                let (word, _) = getopt(text, own.get(at + 1), &SUDO_OPTIONS);
                edits |= git_long(text, "edit")
                    || text.strip_prefix('-').is_some_and(|bundle| {
                        !bundle.starts_with('-')
                            && bundle
                                .chars()
                                .take_while(|letter| {
                                    !SUDO_OPTIONS.short.iter().any(|(s, _)| s == letter)
                                })
                                .any(|letter| letter == 'e')
                    });
                if matches!(word, Word::Value) {
                    2
                } else {
                    1
                }
            }
            _ => 1,
        };
    }
    edits.then(|| &args[start..])
}

/// `sudo`'s options (sudo.ws, `sudo --help`).
const SUDO_OPTIONS: Getopt = Getopt {
    short: &[
        ('C', "close-from"),
        ('D', "chdir"),
        ('g', "group"),
        ('h', "host"),
        ('p', "prompt"),
        ('R', "chroot"),
        ('r', "role"),
        ('T', "command-timeout"),
        ('t', "type"),
        ('U', "other-user"),
        ('u', "user"),
    ],
    long: &[
        ("askpass", false),
        ("background", false),
        ("bell", false),
        ("chdir", true),
        ("chroot", true),
        ("close-from", true),
        ("command-timeout", true),
        ("edit", false),
        ("group", true),
        ("help", false),
        ("host", true),
        ("list", false),
        ("login", false),
        ("non-interactive", false),
        ("other-user", true),
        ("preserve-env", false),
        ("preserve-groups", false),
        ("prompt", true),
        ("remove-timestamp", false),
        ("reset-timestamp", false),
        ("role", true),
        ("set-home", false),
        ("shell", false),
        ("stdin", false),
        ("type", true),
        ("user", true),
        ("validate", false),
        ("version", false),
    ],
};

/// The options of `doas`, `gsudo` and `pkexec` (read as `sudo`'s) that take
/// the next argument.
const SUDO_VALUES: &[&str] = &[
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
];

/// The options of `run0`, systemd's own `sudo`, that take the next argument.
const RUN0_VALUES: &[&str] = &[
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
];

/// `launch`, which runs the program at `start`, started in the folder the
/// last of the options `names` among the wrapper's own, before `start`,
/// gives (`sudo -D DIR`, `--chdir DIR`, `--chdir=DIR`, `-DDIR`); `values`
/// are the options that take the next argument.
fn started_in(
    args: &[Arg],
    start: Option<usize>,
    names: &[&str],
    values: &[&str],
    launch: Launch,
) -> Launch {
    let (Launch::Runs(_), Some(start)) = (&launch, start) else {
        return launch;
    };
    let own = args.get(..start).unwrap_or_default();
    let folder = folder_option(own, names, true, |text, _| {
        if values.contains(&text) {
            Word::Value
        } else {
            Word::Flag
        }
    });
    in_folder(folder, launch)
}

/// Whether another program's output is piped into the unit.
fn piped(unit: &Unit) -> bool {
    unit.stage.is_some_and(|stage| stage.index > 0)
}

/// Whether the unit is handed an input of its own: another program's output
/// piped into it, or a file, a here-document or a here-string redirected
/// onto it (`python < x.py`).
fn fed(unit: &Unit) -> bool {
    piped(unit) || unit.stdin.is_some()
}

/// What `coproc` runs: the first word past an optional name, the `{` words
/// that open a group (`coproc NAME { { cmd; }; }`), and what stands before a
/// command (`NAME=value` words, `!`). A loop, a conditional or a function
/// after it (`coproc while …; do …; done`, also inside a group) is cut into
/// pieces by the grammar, its body behind the program `do`, so it is not
/// read.
pub(super) fn coproc(args: &[Arg]) -> Launch {
    command_after(args, coproc_name(args), false)
}

/// How many words name a `coproc` (`coproc NAME { … }`): one or none. A
/// name stands before a group or a compound command; before a simple
/// command the first word is the program.
fn coproc_name(args: &[Arg]) -> usize {
    let word = |at: usize| args.get(at).and_then(Arg::known);
    let opens = |at: usize| word(at).is_some_and(opens_group);
    let compound = |at: usize| word(at).is_some_and(|text| COMPOUND.contains(&text));
    let stuck = |at: usize| word(at).is_some_and(stuck_group);
    usize::from(!opens(0) && !stuck(0) && (opens(1) || stuck(1) || compound(1)))
}

/// How many groups a `coproc` opens when its words past the name are only
/// `{` words, the group's commands on the lines after it (`coproc NAME {`,
/// a newline, `ls`): `None` when it has other words, or none.
fn coproc_opens_only(args: &[Arg]) -> Option<usize> {
    let rest = args.get(coproc_name(args)..).unwrap_or_default();
    (!rest.is_empty() && rest.iter().all(|arg| arg.known().is_some_and(opens_group)))
        .then(|| coproc_groups(rest))
}

/// The groups `args`, a zsh `repeat`'s, open, and whether they open a list
/// after `do`, when nothing comes after them: `repeat 3 {` and `repeat 3
/// do` with the body on the lines after them.
fn repeat_opens_only(args: &[Arg]) -> Option<(usize, bool)> {
    let rest = args.get(1..).unwrap_or_default();
    let mut opens_do = false;
    for arg in rest {
        match arg.known() {
            Some("do") => opens_do = true,
            Some(text) if opens_group(text) => {}
            _ => return None,
        }
    }
    (!rest.is_empty()).then(|| (coproc_groups(rest), opens_do))
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

/// Note the command after the assignments a word that starts a command steps
/// over (`time -p PATH=/tmp/e f`): it is a command with an assignment in front
/// of it.
fn note_stepped_assignments(split: &mut Split, args: &[Arg]) {
    let Some(first) = args
        .iter()
        .take(8)
        .position(|arg| arg.known().is_some_and(is_assignment))
    else {
        return;
    };
    let words: Vec<&str> = args[first..]
        .iter()
        .filter_map(Arg::known)
        .skip_while(|word| is_assignment(word))
        .collect();
    split.note_prefixed(&words);
}

/// How many groups the words before what a `coproc` (or `time`, `!`,
/// `repeat`) runs open: each `{` of the words [`command_after`] steps over
/// (`{ {` is one word, two groups).
fn coproc_groups(own: &[Arg]) -> usize {
    own.iter()
        .filter_map(Arg::known)
        .filter(|text| opens_group(text))
        .map(|text| text.matches('{').count())
        .sum()
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

/// The multi-call firewall programs, which run the program they name.
const MULTI_CALL: [&str; 3] = ["xtables-nft-multi", "xtables-legacy-multi", "xtables-multi"];

/// The program a multi-call firewall program runs: it also takes its own
/// short names, `main4` for `iptables`, `main6` for `ip6tables` and
/// `restore4`, `restore6`, `save4` and `save6` for their `-restore` and
/// `-save`.
fn applet(unit: &mut Unit) {
    let program = match unit.key().as_deref() {
        Some("main4") => "iptables",
        Some("main6") => "ip6tables",
        Some("restore4") => "iptables-restore",
        Some("restore6") => "ip6tables-restore",
        Some("save4") => "iptables-save",
        Some("save6") => "ip6tables-save",
        _ => return,
    };
    unit.program = Arg::Known(program.to_string());
}

pub(super) fn runs(args: &[Arg], start: Option<usize>) -> Launch {
    start
        .filter(|start| *start < args.len())
        .map_or(Launch::Itself, Launch::Runs)
}

/// The index of the first argument at or after `start` that is not a
/// `NAME=value` word: sudo sets those in the environment of the program
/// after them (`sudo TF_CLI_ARGS=-destroy terraform apply`).
fn after_assignments(args: &[Arg], start: usize) -> usize {
    let mut at = start;
    while args.get(at).is_some_and(|arg| {
        arg.text()
            .trim_start_matches(['"', '\''])
            .split_once('=')
            .is_some_and(|(name, _)| {
                name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
    }) {
        at += 1;
    }
    at
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

/// [`after_options`] for a program that reads its options as `getopt`
/// does: short letters in a bundle, where a letter of `short` takes the rest
/// of the bundle or, at its end, the next word (`-fo log`); a long option of
/// `long` takes the next word unless its value follows `=`.
pub(super) fn after_getopt(args: &[Arg], short: &str, long: &[&str]) -> Option<usize> {
    after_options_by(args, |text, _| getopt_word(text, short, long))
}

/// What the option `text` is among options read as [`after_getopt`] reads
/// them.
pub(super) fn getopt_word(text: &str, short: &str, long: &[&str]) -> Word {
    if let Some(name) = text.strip_prefix("--") {
        return if long.contains(&name) {
            Word::Value
        } else {
            Word::Flag
        };
    }
    let bundle = text.strip_prefix('-').unwrap_or(text);
    for (at, letter) in bundle.char_indices() {
        if short.contains(letter) {
            return if at + letter.len_utf8() == bundle.len() {
                Word::Value
            } else {
                Word::Flag
            };
        }
    }
    Word::Flag
}

/// The value of the option `letter` (also in a bundle, `-qc CMD`, or
/// attached, `-cCMD`) or `--name` (also `--name=value`), wherever it stands
/// before a `--`, as a program that reads its options as `getopt` does finds
/// it among its operands; `short` and `long` are the other options that take
/// a value, whose values are skipped.
pub(super) fn getopt_value(
    args: &[Arg],
    letter: Option<char>,
    name: &str,
    short: &str,
    long: &[&str],
) -> Option<Arg> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        if let Some(option) = text.strip_prefix("--") {
            let (option, value) = option
                .split_once('=')
                .map_or((option, None), |(option, value)| (option, Some(value)));
            if option == name {
                return value.map_or_else(
                    || args.get(at).cloned(),
                    |value| Some(Arg::Known(value.to_string())),
                );
            }
            if value.is_none() && long.contains(&option) {
                at += 1;
            }
        } else if let Some(bundle) = text.strip_prefix('-') {
            for (index, found) in bundle.char_indices() {
                let rest = &bundle[index + found.len_utf8()..];
                if Some(found) == letter {
                    return if rest.is_empty() {
                        args.get(at).cloned()
                    } else {
                        Some(Arg::Known(rest.to_string()))
                    };
                }
                if short.contains(found) {
                    at += usize::from(rest.is_empty());
                    break;
                }
            }
        }
    }
    None
}

/// The index after the subcommand `word`, the first word after the options
/// of the program (read as [`after_getopt`] reads them).
pub(super) fn subcommand(args: &[Arg], word: &str, short: &str, long: &[&str]) -> Option<usize> {
    let at = after_getopt(args, short, long)?;
    (args.get(at)?.known()? == word).then_some(at + 1)
}

/// `text` as one word of a POSIX shell line: as it is when the shell would
/// read it so, in single quotes otherwise. A quoted `~` names the home
/// directory to the guard as much as a bare one, as every other path it
/// reads, so quoting never hides one.
pub(super) fn shell_word(text: &str) -> String {
    let plain = !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./~:=@%+,-".contains(c));
    if plain {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// Arguments made into a POSIX shell line that runs them as they are, each
/// one word ([`shell_word`]). Unknown when any of them is.
pub(super) fn shell_words(args: &[Arg]) -> Arg {
    let line = args
        .iter()
        .map(|arg| {
            arg.known()
                .map_or_else(|| arg.text().to_string(), shell_word)
        })
        .collect::<Vec<_>>()
        .join(" ");
    if args.iter().all(|arg| arg.known().is_some()) {
        Arg::Known(line)
    } else {
        Arg::Unknown(line)
    }
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
