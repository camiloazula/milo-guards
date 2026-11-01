//! The wrappers that run another program or script: `env`, `xargs`,
//! `rsync -e`, `tmux`, `cmd /c`, `powershell -Command`, `Start-Process`,
//! cmd's `start` and the package runners (`npx`, `uvx`, `bunx`, ...).

use super::{after_options, is_stdin, join, option_value, Launch};
use crate::powershell::Params;
use crate::unit::{self, has_flag, Arg, Reads, Unit};
use crate::Shell;

/// The command `rsync -e` (`--rsh`) runs: also at the end of a bundle
/// (`-avze 'ssh -p 22'`) or joined (`-essh`, `--rsh=ssh`).
pub(super) fn rsh(args: &[Arg]) -> Option<Arg> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        if let Some(command) = text.strip_prefix("--rsh=") {
            return Some(Arg::Known(command.to_string()));
        }
        if text == "--rsh" {
            return iter.next().cloned();
        }
        if let Some(bundle) = text
            .strip_prefix('-')
            .filter(|bundle| !bundle.starts_with('-'))
        {
            if bundle.ends_with('e') {
                return iter.next().cloned();
            }
            if let Some(command) = bundle.strip_prefix('e').filter(|rest| !rest.is_empty()) {
                return Some(Arg::Known(command.to_string()));
            }
        }
    }
    None
}

/// `env`: assignments and options, then the program; `-S` splits a string
/// into the command.
pub(super) fn env(args: &[Arg]) -> Launch {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("-S" | "--split-string") => {
                return args.get(at + 1).map_or(Launch::Itself, |script| {
                    Launch::Script(Shell::Posix, script.clone())
                });
            }
            Some("-u" | "--unset" | "-C" | "--chdir") => at += 2,
            Some(text)
                if text.starts_with('-') || (text.contains('=') && !text.starts_with('=')) =>
            {
                at += 1;
            }
            _ => return Launch::Runs(at),
        }
    }
    Launch::Itself
}

/// The variables `env` sets (`X=1`) or unsets (`-u X`) for the program it
/// runs, read as [`env`] reads its arguments.
pub(super) fn env_sets(args: &[Arg]) -> Vec<String> {
    let mut names = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("-S" | "--split-string") => break,
            Some("-u" | "--unset") => {
                names.extend(args.get(at + 1).map(|name| name.text().to_string()));
                at += 2;
            }
            Some("-C" | "--chdir") => at += 2,
            Some(text) if text.starts_with("--unset=") => {
                names.push(text["--unset=".len()..].to_string());
                at += 1;
            }
            // `-uPATH`, and `-iu PATH` (which `env` reads as `-iu` and then
            // a program called `PATH`): the name is attached or next.
            Some(text)
                if text.starts_with('-') && !text.starts_with("--") && text.contains('u') =>
            {
                let rest = text.split_once('u').map_or("", |(_, rest)| rest);
                if rest.is_empty() {
                    names.extend(args.get(at + 1).map(|name| name.text().to_string()));
                } else {
                    names.push(rest.to_string());
                }
                at += 1;
            }
            Some(text) if text.starts_with('-') => at += 1,
            Some(text) if text.contains('=') && !text.starts_with('=') => {
                names.extend(text.split('=').next().map(str::to_string));
                at += 1;
            }
            _ => break,
        }
    }
    names
}

/// `xargs`: its options, then the program its input is handed to.
pub(super) fn xargs(args: &[Arg]) -> Launch {
    let mut replace = None;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            break;
        };
        match text {
            "-I" => {
                replace = args.get(at + 1).and_then(Arg::known).map(str::to_string);
                at += 2;
            }
            "-J" => {
                replace = args.get(at + 1).and_then(Arg::known).map(str::to_string);
                at += 2;
            }
            "-n" | "-P" | "-L" | "-s" | "-d" | "-E" | "-a" | "-R" | "-S" | "--max-args"
            | "--max-procs" | "--max-lines" | "--max-chars" | "--delimiter" | "--eof"
            | "--arg-file" | "--process-slot-var" => at += 2,
            text if text.starts_with("-I") => {
                replace = Some(text[2..].to_string());
                at += 1;
            }
            text if text.starts_with("--replace=") => {
                replace = Some(text["--replace=".len()..].to_string());
                at += 1;
            }
            text if text.starts_with("-i") => {
                replace = Some(if text.len() > 2 {
                    text[2..].to_string()
                } else {
                    "{}".to_string()
                });
                at += 1;
            }
            text if text.starts_with('-') && text.len() > 1 => at += 1,
            _ => break,
        }
    }
    if at < args.len() {
        Launch::Input { start: at, replace }
    } else {
        Launch::Itself
    }
}

/// `tmux` runs a command through the user's shell in its sessions and
/// windows: the last operand of such a subcommand is that command.
pub(super) fn tmux(args: &[Arg]) -> Launch {
    let runs = args.iter().filter_map(Arg::known).any(|text| {
        matches!(
            text,
            "new"
                | "new-session"
                | "neww"
                | "new-window"
                | "splitw"
                | "split-window"
                | "respawnp"
                | "respawn-pane"
                | "respawnw"
                | "respawn-window"
                | "send-keys"
                | "send"
        )
    });
    match args
        .iter()
        .rev()
        .find(|arg| arg.known().is_some_and(|text| !text.starts_with('-')))
    {
        Some(command) if runs => Launch::Script(Shell::Posix, command.clone()),
        _ => Launch::Itself,
    }
}

/// `cmd /c …` or `cmd /k …` runs the rest of the line in cmd; without
/// either, cmd reads commands from its input.
pub(super) fn cmd(args: &[Arg]) -> Launch {
    for (at, arg) in args.iter().enumerate() {
        let Some(text) = arg.known() else { continue };
        let lower = text.to_ascii_lowercase();
        if lower == "/c" || lower == "/k" || lower == "/r" {
            return Launch::Script(Shell::Cmd, join(&args[at + 1..]));
        }
        if let Some(rest) = ["/c", "/k", "/r"]
            .iter()
            .find_map(|switch| lower.strip_prefix(switch))
        {
            if !rest.starts_with(' ') && !rest.is_empty() && !rest.starts_with(':') {
                let mut script = vec![Arg::Known(text[2..].to_string())];
                script.extend(args[at + 1..].iter().cloned());
                return Launch::Script(Shell::Cmd, join(&script));
            }
        }
    }
    if unit::plain(args).is_empty() {
        Launch::Reads(Reads::Shell)
    } else {
        Launch::Itself
    }
}

/// `powershell` and `pwsh`: `-Command` (or, in Windows PowerShell, a first
/// argument that is not a parameter) runs the rest; `-EncodedCommand` runs
/// what cannot be read; `-File` runs a script file; with none of them it
/// reads commands from its input.
pub(super) fn powershell(args: &[Arg]) -> Launch {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            return Launch::Script(Shell::PowerShell, join(&args[at..]));
        };
        let Some(name) = text.strip_prefix('-').or_else(|| text.strip_prefix('/')) else {
            return Launch::Script(Shell::PowerShell, join(&args[at..]));
        };
        let name = name.trim_end_matches(':').to_ascii_lowercase();
        if name.is_empty() {
            return Launch::Reads(Reads::Shell);
        }
        if matches!(name.as_str(), "help" | "h" | "?") {
            return Launch::Itself;
        }
        // `-Version 2` picks the engine and the command after it still runs;
        // `-Version` alone prints the version.
        if name == "v" || (name.len() >= 2 && "version".starts_with(&name)) {
            let value = args
                .get(at + 1)
                .and_then(Arg::known)
                .is_some_and(|next| !next.starts_with(['-', '/']));
            if !value {
                return Launch::Itself;
            }
            at += 2;
        } else if matches!(name.as_str(), "ex" | "ep")
            || (name.len() >= 3 && "executionpolicy".starts_with(&name))
        {
            at += 2;
        } else if name == "e"
            || name == "ec"
            || (name.len() >= 2 && "encodedcommand".starts_with(&name))
        {
            return Launch::Encoded;
        } else if "command".starts_with(&name) {
            let rest = &args[at + 1..];
            return match rest {
                [] => Launch::Itself,
                [only] if only.known() == Some("-") => Launch::Reads(Reads::Shell),
                rest => Launch::Script(Shell::PowerShell, join(rest)),
            };
        } else if "file".starts_with(&name) {
            return match args.get(at + 1) {
                Some(Arg::Known(stdin)) if is_stdin(stdin) => Launch::Reads(Reads::Shell),
                Some(Arg::Known(_)) | None => Launch::Itself,
                Some(script) => Launch::Script(Shell::PowerShell, script.clone()),
            };
        } else if matches!(
            name.as_str(),
            "windowstyle"
                | "w"
                | "win"
                | "configurationname"
                | "outputformat"
                | "of"
                | "o"
                | "inputformat"
                | "if"
                | "workingdirectory"
                | "wd"
                | "settingsfile"
                | "custompipename"
        ) {
            at += 2;
        } else {
            at += 1;
        }
    }
    Launch::Reads(Reads::Shell)
}

/// `Start-Process`: the program in `-FilePath` (or first), its arguments in
/// `-ArgumentList` (or after it), and `-Verb RunAs` to run it elevated.
pub(super) fn start_process(unit: &Unit) -> Launch {
    let params = Params::read(&unit.args);
    let mut positional = params.positional.iter();
    let program = params
        .values(&["filepath"])
        .first()
        .copied()
        .or_else(|| positional.next().copied());
    let Some(program) = program else {
        return Launch::Itself;
    };
    let mut args = Vec::new();
    for arg in params
        .values(&["argumentlist"])
        .into_iter()
        .chain(positional.copied())
    {
        match arg {
            Arg::Known(text) => args.extend(
                text.split_whitespace()
                    .map(|word| Arg::Known(word.to_string())),
            ),
            other => args.push(other.clone()),
        }
    }
    let mut wrappers = unit.wrappers.clone();
    wrappers.push("start-process".to_string());
    if params.values(&["verb"]).iter().any(|verb| {
        verb.known()
            .is_some_and(|verb| verb.eq_ignore_ascii_case("runas"))
    }) {
        wrappers.push("runas".to_string());
    }
    Launch::Replace(Box::new(Unit {
        shell: unit.shell,
        program: program.clone(),
        args,
        wrappers,
        stage: unit.stage,
        reads: Reads::Nothing,
        dir: None,
        hidden: false,
    }))
}

/// cmd's `start`: a quoted title first, its `/` options, then the program.
pub(super) fn start(args: &[Arg]) -> Launch {
    let mut at = 0;
    if args
        .first()
        .and_then(Arg::known)
        .is_some_and(|title| title.is_empty() || title.contains(char::is_whitespace))
    {
        at = 1;
    }
    while let Some(arg) = args.get(at) {
        match arg.known().map(str::to_ascii_lowercase) {
            Some(text) if matches!(text.as_str(), "/d" | "/affinity" | "/node") => at += 2,
            Some(text) if text.starts_with('/') => at += 1,
            _ => return Launch::Runs(at),
        }
    }
    Launch::Itself
}

/// The delete tools that come as packages: a package runner or a package
/// manager's bin directory starts them.
pub(crate) const DELETERS: [&str; 5] = ["rimraf", "del", "del-cli", "premove", "rmrf"];

/// The options of `npx` and `npm exec` that take the next argument.
const NPM_VALUES: [&str; 14] = [
    "-p",
    "--package",
    "-c",
    "--call",
    "-w",
    "--workspace",
    "--registry",
    "--cache",
    "--prefix",
    "--userconfig",
    "--globalconfig",
    "--loglevel",
    "--node-arg",
    "--script-shell",
];

/// The options of `pnpm`, before and after `dlx` and `exec`, that take the
/// next argument.
const PNPM_VALUES: [&str; 11] = [
    "-C",
    "--dir",
    "-F",
    "--filter",
    "--filter-prod",
    "--reporter",
    "--loglevel",
    "-p",
    "--package",
    "--registry",
    "--config",
];

/// The options of `yarn`, before and after `dlx` and `exec`, that take the
/// next argument.
const YARN_VALUES: [&str; 3] = ["--cwd", "-p", "--package"];

/// The options of `bunx` and `bun x` that take the next argument.
const BUN_X_VALUES: [&str; 2] = ["-p", "--package"];

/// The options of `uv`, `uvx`, `uv run` and `uv tool run` that take the next
/// argument. `--from` names the package, the program follows it.
const UV_VALUES: [&str; 39] = [
    "--from",
    "--with",
    "-w",
    "--with-requirements",
    "--with-editable",
    "-p",
    "--python",
    "--index",
    "--default-index",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-c",
    "--constraints",
    "--overrides",
    "--env-file",
    "--config-file",
    "--directory",
    "--project",
    "--cache-dir",
    "--refresh-package",
    "--reinstall-package",
    "-P",
    "--upgrade-package",
    "--index-strategy",
    "--keyring-provider",
    "--resolution",
    "--prerelease",
    "--exclude-newer",
    "--link-mode",
    "--config-setting",
    "-C",
    "--allow-insecure-host",
    "--build-constraints",
    "--color",
    "--python-platform",
    "--package",
];

/// The options of `pipx` and `pipx run` that take the next argument.
const PIPX_VALUES: [&str; 5] = [
    "--spec",
    "--python",
    "--index-url",
    "--pip-args",
    "--fetch-missing-python",
];

/// Where the program of a package runner starts: the words that lead to it
/// (each with the options that may stand before it), then the options of
/// the runner. The first index is where the runner's own options start,
/// the second the program, when there is one.
fn locate(
    args: &[Arg],
    steps: &[(&[&str], &[&str])],
    own: &[&str],
) -> Option<(usize, Option<usize>)> {
    let mut from = 0;
    for (values, words) in steps {
        let at = from + after_options(args.get(from..)?, values)?;
        if !args
            .get(at)?
            .known()
            .is_some_and(|text| words.contains(&text))
        {
            return None;
        }
        from = at + 1;
    }
    let program = args
        .get(from..)
        .and_then(|rest| after_options(rest, own))
        .map(|at| from + at);
    Some((from, program))
}

/// A package runner: `npx`, `npm exec`, `pnpm dlx`, `pnpm exec`,
/// `yarn dlx`, `yarn exec`, `bunx`, `bun x`, `uvx`, `uv tool run`,
/// `uv run`, `pipx run`. It runs the program it names, so that program is
/// judged, with a version after the package taken off (`rimraf@5`). Where
/// the runner names the package apart from the program (`npx -p pkg prog`,
/// `uvx --from pkg prog`) the program is the one after the options. `npx -c`
/// and `pnpm exec -c` run a shell command instead. `pnpm` and `yarn` also
/// start a delete tool of the project by its name (`pnpm rimraf dist`).
pub(super) fn runner(key: &str, unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    let found = match key {
        "npx" => Some((0, after_options(args, &NPM_VALUES))),
        "bunx" => Some((0, after_options(args, &BUN_X_VALUES))),
        "uvx" => Some((0, after_options(args, &UV_VALUES))),
        "npm" => locate(args, &[(&NPM_VALUES, &["exec", "x"])], &NPM_VALUES),
        "pnpm" => locate(args, &[(&PNPM_VALUES, &["dlx", "exec"])], &PNPM_VALUES)
            .or_else(|| direct(args, &PNPM_VALUES)),
        "yarn" => locate(args, &[(&YARN_VALUES, &["dlx", "exec"])], &YARN_VALUES)
            .or_else(|| direct(args, &YARN_VALUES)),
        "bun" => locate(args, &[(&[], &["x"])], &BUN_X_VALUES),
        "uv" => locate(
            args,
            &[(&UV_VALUES, &["tool"]), (&[], &["run"])],
            &UV_VALUES,
        )
        .or_else(|| locate(args, &[(&UV_VALUES, &["run"])], &UV_VALUES)),
        "pipx" => locate(args, &[(&[], &["run"])], &PIPX_VALUES),
        _ => None,
    };
    let Some((from, program)) = found else {
        return Launch::Itself;
    };
    let own = args
        .get(from..program.unwrap_or(args.len()))
        .unwrap_or_default();
    let shell = if unit.shell == Shell::Cmd {
        Shell::Cmd
    } else {
        Shell::Posix
    };
    match key {
        "npx" | "npm" => {
            if let Some(script) = option_value(own, "-c", "--call") {
                return Launch::Script(shell, script);
            }
        }
        "pnpm" if has_flag(own, Some('c'), Some("shell-mode")) => {
            if let Some(program) = program {
                return Launch::Script(shell, join(&args[program..]));
            }
        }
        _ => {}
    }
    let Some(program) = program else {
        return Launch::Itself;
    };
    Launch::Replace(Box::new(running(unit, key, program)))
}

/// `pnpm rimraf dist` and `yarn rimraf dist`: the project's own delete tool.
fn direct(args: &[Arg], values: &[&str]) -> Option<(usize, Option<usize>)> {
    let at = after_options(args, values)?;
    let name = args.get(at)?.known()?;
    DELETERS.contains(&name).then_some((at, Some(at)))
}

/// The unit a runner runs: the program at `program`, as a package without
/// its version, with the arguments after it.
pub(super) fn running(unit: &Unit, key: &str, program: usize) -> Unit {
    let mut wrappers = unit.wrappers.clone();
    wrappers.push(key.to_string());
    Unit {
        shell: unit.shell,
        program: without_version(&unit.args[program]),
        args: unit.args[program + 1..].to_vec(),
        wrappers,
        stage: unit.stage,
        reads: Reads::Nothing,
        dir: None,
        hidden: false,
    }
}

/// `rimraf@5` and `@scope/tool@1.2` name a package and its version: the
/// program is the package. A path or a URL is left as it is.
pub(super) fn without_version(program: &Arg) -> Arg {
    let Arg::Known(text) = program else {
        return program.clone();
    };
    if !text.starts_with('@') && text.contains(['/', '\\', ':']) {
        return program.clone();
    }
    let from = if text.starts_with('@') {
        text.find('/').map_or(text.len(), |at| at + 1)
    } else {
        0
    };
    match text[from..].find('@') {
        Some(at) if from + at > 0 => Arg::Known(text[..from + at].to_string()),
        _ => program.clone(),
    }
}
