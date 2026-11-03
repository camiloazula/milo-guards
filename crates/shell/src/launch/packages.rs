//! The runners of a project's environment (`poetry run`, `conda run`,
//! `mise exec`), the package managers' own ways of naming a command (`yarn
//! workspace NAME`, `corepack pnpm`), the packages that run a command
//! (`shx`, `cross-env`, `concurrently`, `npm-run-all`), and the programs a
//! package installs under another name (`aws-cdk` is `cdk`).

use super::wrappers::subcommand;
use super::{after_assignments, after_options, join, Launch, MAX_FORKS};
use crate::unit::{Arg, Unit, MAX_LEN};
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
        // hatch's global options, and those of `hatch env run` that take a
        // value; the environment may also stand in front of the command
        // (`hatch run test:cov`, see [`hatch_command`]), and the matrix
        // variables before it (`hatch run +py=3.12 cov`, see
        // [`past_selectors`]).
        "hatch" => &[
            "-e",
            "--env",
            "-p",
            "--project",
            "--data-dir",
            "--cache-dir",
            "--config",
            "-i",
            "--include",
            "-x",
            "--exclude",
            "-f",
            "--filter",
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
            "--log-level",
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
        "pipenv" => &["--python", "--pypi-mirror"],
        // The tool versions and environment `volta run` gives the command.
        "volta" => &["--node", "--npm", "--pnpm", "--yarn", "--env"],
        _ => return None,
    })
}

/// The options of `pixi exec` that take the next word: the packages it
/// installs (`-s python`), their channels and platform, besides pixi's own.
pub(super) const PIXI_EXEC_VALUES: &[&str] = &[
    "-s",
    "--spec",
    "-w",
    "--with",
    "-c",
    "--channel",
    "-p",
    "--platform",
    "--color",
    "--concurrent-solves",
    "--concurrent-downloads",
    "--pypi-keyring-provider",
    "--auth-file",
    "--tls-root-certs",
];

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

/// The line `mise exec -c` (`--command`) runs among `args`, the options of
/// `mise exec`: the next word, or the value joined to the option (`-c'cmd'`,
/// `-c=cmd`, `--command=cmd`), as mise's option parser reads it.
pub(super) fn mise_command(args: &[Arg]) -> Option<Arg> {
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            return None;
        }
        if text == "-c" || text == "--command" {
            return words.next().cloned();
        }
        let joined = text.strip_prefix("--command=").or_else(|| {
            text.strip_prefix("-c")
                .filter(|rest| !rest.is_empty() && !text.starts_with("--"))
                .map(|rest| rest.strip_prefix('=').unwrap_or(rest))
        });
        if let Some(value) = joined {
            return Some(Arg::Known(value.to_string()));
        }
    }
    None
}

/// Where the command of `hatch run` starts, from `at`: past the matrix
/// variables that pick its environments (`+py=3.12`, and `-py=3.10`, which
/// leaves one out). `None` when only those follow.
pub(super) fn past_selectors(args: &[Arg], at: usize) -> Option<usize> {
    let skip = args
        .get(at..)?
        .iter()
        .take_while(|arg| {
            arg.known().is_some_and(|text| {
                (text.starts_with('+') || text.starts_with('-')) && text.contains('=')
            })
        })
        .count();
    (at + skip < args.len()).then_some(at + skip)
}

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
    while let Some(step) = args
        .get(at..)
        .and_then(|rest| subcommand(rest, values, &["workspace", "workspaces"]))
    {
        let word = |offset: usize| args.get(at + step + offset).and_then(Arg::known);
        let next = match (word(0), word(1)) {
            (Some("workspace"), Some(_)) => at + step + 2,
            // yarn 1's `yarn workspaces run NAME` runs `yarn run NAME` in
            // each workspace.
            (Some("workspaces"), Some("run")) => at + step + 1,
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
const PACKAGE_PROGRAMS: [(&str, &str); 7] = [
    ("aws-cdk", "cdk"),
    ("cdktf-cli", "cdktf"),
    ("firebase-tools", "firebase"),
    ("awscli", "aws"),
    ("azure-cli", "az"),
    ("dotenv-cli", "dotenv"),
    ("npm-run-all2", "npm-run-all"),
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
        "concurrently" => concurrently(args, shell),
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

/// The lines `concurrently` runs, with their shortcuts spelt out. With
/// `-P` (`--passthrough-arguments`) the words after `--` are no lines: they
/// fill in the placeholders of the lines (`{1}`, `{@}`, `{*}`), quoted as
/// concurrently quotes them for the shell.
fn concurrently(args: &[Arg], shell: Shell) -> Vec<Arg> {
    let split = args.iter().position(|arg| arg.known() == Some("--"));
    let options = &args[..split.unwrap_or(args.len())];
    let passes = options.iter().filter_map(Arg::known).any(|text| {
        matches!(
            text,
            "-P" | "--passthrough-arguments" | "--passthrough-arguments=true"
        )
    });
    if !passes {
        return strings(args, CONCURRENTLY_VALUES, &["--teardown"])
            .into_iter()
            .map(shortcut)
            .collect();
    }
    let passed = split.map_or(&[][..], |at| &args[at + 1..]);
    strings(options, CONCURRENTLY_VALUES, &["--teardown"])
        .into_iter()
        .map(|line| fill_in(&shortcut(line), passed, shell))
        .collect()
}

/// `line` with its placeholders filled in from `passed`: `{N}` is the N-th
/// word, `{@}` each word, `{*}` all of them as one, each quoted for
/// `shell`. A placeholder for a word that is not there is empty. A word
/// only known when the line runs makes the line only known then. Filling
/// in stops past the longest line read, which the line then is.
fn fill_in(line: &Arg, passed: &[Arg], shell: Shell) -> Arg {
    let Arg::Known(text) = line else {
        return line.clone();
    };
    if !text.contains('{') {
        return line.clone();
    }
    let quote = |word: &str| quoted(word, shell);
    let all: Vec<&str> = passed.iter().map(Arg::text).collect();
    let each = all
        .iter()
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" ");
    let whole = quote(&all.join(" "));
    let mut out = String::new();
    let mut rest = text.as_str();
    // Past the longest line the line is not read, so the rest is not
    // filled in: what is there is already too long.
    while let Some(open) = rest.find('{').filter(|_| out.len() <= MAX_LEN) {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let inside = &after[..close];
        let filled = match inside {
            "@" => Some(each.clone()),
            "*" => Some(whole.clone()),
            number => number
                .parse::<usize>()
                .ok()
                .filter(|number| *number > 0)
                .map(|number| {
                    all.get(number - 1)
                        .map_or_else(String::new, |word| quote(word))
                }),
        };
        match filled {
            Some(filled) => out.push_str(&filled),
            None => out.push_str(&rest[open..=open + 1 + close]),
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    if passed.iter().all(|arg| arg.known().is_some()) {
        Arg::Known(out)
    } else {
        Arg::Unknown(out)
    }
}

/// `word` quoted for `shell` as a word of its own: as it is when it holds
/// nothing the shell reads apart (a `~` stays, so the shell expands it, as
/// concurrently leaves it), in quotes otherwise.
fn quoted(word: &str, shell: Shell) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./~:=@%+,".contains(c));
    if plain {
        word.to_string()
    } else if shell == Shell::Posix {
        format!("'{}'", word.replace('\'', "'\\''"))
    } else {
        format!("\"{}\"", word.replace('"', "\"\""))
    }
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

/// The line `npm-run-all` runs for `line`: it runs `npm run` with the
/// script the line names, so a name alone (`format`, `reboot`) or a first
/// word with a wildcard (`watch:*`), a pattern of the project's script
/// names, is a script, not a program. A line with words after its first
/// (`'rimraf ~'`) is also read as it is written, as the program it names.
fn script_pattern(line: Arg) -> Arg {
    let Arg::Known(text) = &line else {
        return line;
    };
    let mut words = text.split_whitespace();
    let pattern = words
        .next()
        .is_some_and(|name| name.contains(['*', '?', '[', '{']));
    if pattern || words.next().is_none() {
        Arg::Known(format!("npm run {text}"))
    } else {
        line
    }
}
