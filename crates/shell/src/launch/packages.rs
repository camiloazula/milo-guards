//! The runners of a project's environment (`poetry run`, `conda run`,
//! `mise exec`), the package managers' own ways of naming a command (`yarn
//! workspace NAME`, `corepack pnpm`), the packages that run a command
//! (`shx`, `cross-env`, `concurrently`, `npm-run-all`), and the programs a
//! package installs under another name (`aws-cdk` is `cdk`).

use super::{after_assignments, after_options, join, Launch, MAX_FORKS};
use crate::unit::{Arg, Unit};
use crate::Shell;

/// The runners of a project's or a tool's environment that run the command
/// after `run` (`poetry run pytest`), with the options of each that take the
/// next word, before `run` and after it.
pub(super) fn run_values(key: &str) -> Option<&'static [&'static str]> {
    Some(match key {
        // poetry's global options that name a folder.
        "poetry" => &["-C", "--directory", "-P", "--project"],
        // pdm's global options and those of `pdm run` that take a value.
        "pdm" => &[
            "-p",
            "--project",
            "-c",
            "--config",
            "-L",
            "--lockfile",
            "--venv",
        ],
        // hatch's global options; the environment may also stand in front of
        // the command (`hatch run test:cov`, see [`hatch_command`]).
        "hatch" => &[
            "-e",
            "--env",
            "-p",
            "--project",
            "--data-dir",
            "--cache-dir",
            "--config",
        ],
        // `conda run`, `mamba run` and `micromamba run`.
        "conda" | "mamba" | "micromamba" => &[
            "-n",
            "--name",
            "-p",
            "--prefix",
            "--cwd",
            "-r",
            "--root-prefix",
            "--rc-file",
            "-a",
            "--attach",
            "-e",
            "--env",
            "--label",
        ],
        "pixi" => &[
            "--manifest-path",
            "-m",
            "-e",
            "--environment",
            "-w",
            "--workspace",
            "--color",
            "--concurrent-solves",
            "--concurrent-downloads",
            "--pypi-keyring-provider",
            "--auth-file",
            "--tls-root-certs",
            "--skip",
        ],
        "rye" => &["--pyproject"],
        // The tool versions and environment `volta run` gives the command.
        "volta" => &["--node", "--npm", "--pnpm", "--yarn", "--env"],
        _ => return None,
    })
}

/// The options of `mise` and `mise exec` that take the next word. The tools
/// stand after them and the command after `--`; `-c` (`--command`) runs a
/// shell line instead.
pub(super) const MISE_VALUES: &[&str] = &[
    "-C",
    "--cd",
    "-E",
    "--env",
    "-j",
    "--jobs",
    "-c",
    "--command",
];

/// The command `hatch run` is given, at `program`: the environment it runs
/// in may stand in front of it (`hatch run test:cov` runs `cov` in `test`).
pub(super) fn hatch_command(program: &Arg) -> Arg {
    match program {
        Arg::Known(text) if !text.contains(['/', '\\']) => text.split_once(':').map_or_else(
            || program.clone(),
            |(_, command)| Arg::Known(command.to_string()),
        ),
        _ => program.clone(),
    }
}

/// The package managers `corepack` starts by name (`corepack pnpm@9 dlx
/// …`), with their own runners.
const COREPACK_MANAGERS: [&str; 5] = ["npm", "npx", "pnpm", "pnpx", "yarn"];

/// Whether `corepack` runs the package manager its first word names: a
/// command of corepack's own (`enable`, `use`) is its own business.
pub(super) fn corepack_runs(args: &[Arg]) -> bool {
    args.first().and_then(Arg::known).is_some_and(|word| {
        let name = word.split_once('@').map_or(word, |(name, _)| name);
        COREPACK_MANAGERS.contains(&name)
    })
}

/// The commands of `yarn` (version 1 and later) and their aliases. `yarn
/// NAME` for any other name runs the script NAME of the project or, when
/// there is none, the program of that name the project has (`yarn cdk
/// destroy`): it is read as that program. `node` is not among them: `yarn
/// node` runs node.
const YARN_COMMANDS: &[&str] = &[
    "access",
    "add",
    "audit",
    "autoclean",
    "bin",
    "cache",
    "check",
    "config",
    "constraints",
    "create",
    "dedupe",
    "dlx",
    "exec",
    "explain",
    "generate-lock-entry",
    "global",
    "help",
    "import",
    "info",
    "init",
    "install",
    "licenses",
    "link",
    "list",
    "login",
    "logout",
    "npm",
    "outdated",
    "owner",
    "pack",
    "patch",
    "patch-commit",
    "plugin",
    "policies",
    "publish",
    "rebuild",
    "remove",
    "run",
    "search",
    "set",
    "stage",
    "start",
    "tag",
    "team",
    "test",
    "unlink",
    "unplug",
    "up",
    "upgrade",
    "upgrade-interactive",
    "version",
    "versions",
    "why",
    "workspace",
    "workspaces",
];

/// Whether `name` is a command of yarn.
pub(super) fn yarn_command(name: &str) -> bool {
    YARN_COMMANDS.contains(&name)
}

/// The options of `yarn workspaces foreach` that take the next word.
const FOREACH_VALUES: [&str; 6] = [
    "--from",
    "-j",
    "--jobs",
    "--include",
    "--exclude",
    "--since",
];

/// `yarn workspace NAME CMD…` runs `yarn CMD…` in the workspace NAME, and
/// `yarn workspaces foreach [options] CMD…` runs it in each workspace: the
/// words of yarn with those taken off, each time they stand in front of the
/// command, its own options (`values`) kept. `None` when there are none.
pub(super) fn yarn_workspace(args: &[Arg], values: &[&str]) -> Option<Vec<Arg>> {
    let mut kept = Vec::new();
    let mut at = 0;
    let mut changed = false;
    while let Some(step) = args.get(at..).and_then(|rest| after_options(rest, values)) {
        let word = |offset: usize| args.get(at + step + offset).and_then(Arg::known);
        let next = match (word(0), word(1)) {
            (Some("workspace"), Some(_)) => at + step + 2,
            (Some("workspaces"), Some("foreach")) => {
                let from = at + step + 2;
                from + args
                    .get(from..)
                    .and_then(|rest| after_options(rest, &FOREACH_VALUES))?
            }
            _ => break,
        };
        kept.extend_from_slice(&args[at..at + step]);
        at = next;
        changed = true;
    }
    changed.then(|| {
        kept.extend_from_slice(args.get(at..).unwrap_or_default());
        kept
    })
}

/// The programs a package installs under a name of their own: the package
/// a runner is given (`npx aws-cdk destroy`) is the program it runs.
const PACKAGE_PROGRAMS: [(&str, &str); 5] = [
    ("aws-cdk", "cdk"),
    ("cdktf-cli", "cdktf"),
    ("firebase-tools", "firebase"),
    ("awscli", "aws"),
    ("azure-cli", "az"),
];

/// The program a runner runs for the package `program` names, without its
/// version: the program the package installs under another name, and for
/// a Python runner (`uvx`, `uv`, `pipx`) the name in front of a version
/// specifier or extras (`rimraf==1.0`, `black[jupyter]`).
pub(super) fn package_program(key: &str, program: Arg) -> Arg {
    let Arg::Known(mut text) = program else {
        return program;
    };
    if matches!(key, "uvx" | "uv" | "pipx") {
        if let Some(at) = text.find(['=', '<', '>', '!', '~', '[', ';']) {
            if at > 0 {
                text.truncate(at);
            }
        }
    }
    let name = PACKAGE_PROGRAMS
        .iter()
        .find(|(package, _)| text.eq_ignore_ascii_case(package))
        .map(|(_, program)| (*program).to_string());
    Arg::Known(name.unwrap_or(text))
}

/// The packages that run a command given as words, from where the command
/// starts: `shx` runs a command of the `shelljs` package by its name (`shx
/// rm -rf dist` is `rm -rf dist`), past its options, which take no value;
/// `cross-env` the command after its `NAME=value` words.
pub(super) fn command_runner(key: &str, args: &[Arg]) -> Option<Launch> {
    let start = match key {
        "shx" => after_options(args, &[])?,
        "cross-env" => after_assignments(args, 0),
        _ => return None,
    };
    Some(super::runs(args, Some(start)))
}

/// The packages that run shell lines given as strings: `cross-env-shell`
/// runs the words after its `NAME=value` words as one line; `concurrently`
/// each of its arguments (and its `--teardown`); `npm-run-all`, `run-s` and
/// `run-p` each of theirs, as the scripts they name with their arguments.
/// A line runs in the system shell: cmd where the line is for Windows.
/// Each line is read, and the riskiest counts.
pub(super) fn line_runner(key: &str, unit: &Unit) -> Option<Launch> {
    let args = unit.args.as_slice();
    let shell = if unit.shell == Shell::Posix {
        Shell::Posix
    } else {
        Shell::Cmd
    };
    let lines = match key {
        "cross-env-shell" => {
            let start = after_assignments(args, 0);
            if start >= args.len() {
                return Some(Launch::Itself);
            }
            vec![join(&args[start..])]
        }
        "concurrently" => strings(args, CONCURRENTLY_VALUES, &["--teardown"])
            .into_iter()
            .map(shortcut)
            .collect(),
        "npm-run-all" | "run-s" | "run-p" => strings(args, &["--npm-path", "--max-parallel"], &[])
            .into_iter()
            .map(script_pattern)
            .collect(),
        _ => return None,
    };
    // Past the forks a line may make it is unreadable whatever the lines
    // hold, so their readings are not built.
    if lines.len() > MAX_FORKS + 1 {
        return Some(Launch::Opaque("reads in too many ways to judge each"));
    }
    let mut readings = lines
        .into_iter()
        .rev()
        .map(|line| Launch::Script(shell, line));
    let last = readings.next()?;
    Some(readings.fold(last, |rest, line| {
        Launch::Either(Box::new(line), Box::new(rest))
    }))
}

/// The options of `concurrently` that take the next word (`--teardown`
/// takes a line it runs).
const CONCURRENTLY_VALUES: &[&str] = &[
    "-n",
    "--names",
    "--name-separator",
    "-s",
    "--success",
    "-p",
    "--prefix",
    "-c",
    "--prefix-colors",
    "-l",
    "--prefix-length",
    "-t",
    "--timestamp-format",
    "-m",
    "--max-processes",
    "--restart-tries",
    "--restart-after",
    "--kill-signal",
    "--kill-timeout",
    "--default-input-target",
    "--hide",
    "--teardown",
];

/// The words of `args` that are no option and no option's value, wherever
/// they stand, and the values of the options in `lines`, which are lines
/// too. An option that `values` does not list may take the word after it or
/// not, so that word is read as a line.
fn strings(args: &[Arg], values: &[&str], lines: &[&str]) -> Vec<Arg> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => {
                found.extend_from_slice(&args[at + 1..]);
                break;
            }
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                let option = text.split_once('=').map_or(text, |(option, _)| option);
                let attached = text.split_once('=').map(|(_, value)| value);
                if lines.contains(&option) {
                    match attached {
                        Some(value) => found.push(Arg::Known(value.to_string())),
                        None => found.extend(args.get(at + 1).cloned()),
                    }
                }
                at += if attached.is_none() && values.contains(&option) {
                    2
                } else {
                    1
                };
            }
            _ => {
                found.push(arg.clone());
                at += 1;
            }
        }
    }
    found
}

/// The shortcuts `concurrently` reads in front of a command: `npm:NAME`
/// runs `npm run NAME` (also `yarn:`, `pnpm:` and `bun:`), `node:NAME` runs
/// `node --run NAME` and `deno:NAME` runs `deno task NAME`.
const SHORTCUTS: [(&str, &str); 6] = [
    ("npm:", "npm run "),
    ("yarn:", "yarn run "),
    ("pnpm:", "pnpm run "),
    ("bun:", "bun run "),
    ("node:", "node --run "),
    ("deno:", "deno task "),
];

/// The line `concurrently` runs for `line`, with its shortcut spelt out
/// (`npm:dev:*` is `npm run dev:*`, whose pattern names scripts).
fn shortcut(line: Arg) -> Arg {
    let Arg::Known(text) = &line else {
        return line;
    };
    SHORTCUTS
        .iter()
        .find_map(|(prefix, command)| {
            text.strip_prefix(prefix)
                .map(|rest| Arg::Known(format!("{command}{rest}")))
        })
        .unwrap_or(line)
}

/// The line `npm-run-all` runs for `line`: a first word with a wildcard
/// (`watch:*`) is a pattern of the project's script names, run by `npm
/// run`, not a program; any other line is read as it is written.
fn script_pattern(line: Arg) -> Arg {
    let Arg::Known(text) = &line else {
        return line;
    };
    let pattern = text
        .split_whitespace()
        .next()
        .is_some_and(|name| name.contains(['*', '?', '[', '{']));
    if pattern {
        Arg::Known(format!("npm run {text}"))
    } else {
        line
    }
}
