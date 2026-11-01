//! Shells and interpreters given a script, inline code, or their input:
//! which is which, and the perl in-place edits read like `sed -i`.

use super::wrappers::{runner, running, without_version, DELETERS};
use super::{after_options, is_stdin, Launch};
use crate::unit::{Arg, Reads, Unit};
use crate::Shell;

/// The POSIX shells, which run a script with `-c` or read one from their
/// input.
pub(crate) const SHELLS: [&str; 11] = [
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "csh", "tcsh",
];

/// Language interpreters that read code from their input when given no
/// script.
pub(crate) const INTERPRETERS: [&str; 11] = [
    "python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "bun", "deno",
];

/// A POSIX shell: `-c` runs its first operand; a script file is its own
/// business; with neither, it reads commands from its input.
pub(super) fn shell(args: &[Arg]) -> Launch {
    let mut command = false;
    let mut stdin = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            return Launch::Script(Shell::Posix, arg.clone());
        };
        match text {
            "--" => break,
            "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file" => {
                iter.next();
            }
            "-" => {
                stdin = true;
                break;
            }
            text if text.starts_with("--") => {}
            text if (text.starts_with('-') || text.starts_with('+')) && text.len() > 1 => {
                if text[1..].contains('c') {
                    command = true;
                }
                if text[1..].contains('s') {
                    stdin = true;
                }
            }
            _ => {
                return if command {
                    Launch::Script(Shell::Posix, arg.clone())
                } else if stdin || is_stdin(text) {
                    Launch::Reads(Reads::Shell)
                } else {
                    Launch::Itself
                };
            }
        }
    }
    match (command, iter.next()) {
        (true, Some(script)) => Launch::Script(Shell::Posix, script.clone()),
        (true, None) => Launch::Itself,
        (false, Some(Arg::Known(script))) if !stdin && !is_stdin(script) => Launch::Itself,
        (false, Some(script)) if !stdin && script.known().is_none() => {
            Launch::Script(Shell::Posix, script.clone())
        }
        _ => Launch::Reads(Reads::Shell),
    }
}

/// `trap ACTION SIGNAL…`: the action is a script that runs later, in this
/// shell. `trap -p` and `trap -l` print, `trap - SIGNAL` puts the default
/// back and `trap '' SIGNAL` ignores the signal: none runs anything.
pub(super) fn trap(args: &[Arg]) -> Launch {
    match trap_operands(args) {
        None => Launch::Itself,
        Some((action, _)) => Launch::Script(Shell::Posix, action.clone()),
    }
}

/// The action of a `trap` and its signals, when the command sets one.
fn trap_operands(args: &[Arg]) -> Option<(&Arg, &[Arg])> {
    let mut rest = args;
    if let Some(Arg::Known(first)) = rest.first() {
        if first == "--" {
            rest = &rest[1..];
        } else if first.len() > 1
            && first.starts_with('-')
            && first[1..]
                .chars()
                .all(|letter| matches!(letter, 'p' | 'l' | 'P'))
        {
            return None;
        }
    }
    match rest.split_first() {
        Some((Arg::Known(action), _)) if action == "-" => None,
        Some((action, signals)) => Some((action, signals)),
        None => None,
    }
}

/// Whether a subshell may copy the trap: zsh copies `ERR` (`ZERR`) and
/// `DEBUG`, bash `ERR` with `set -E` and `DEBUG` and `RETURN` with `set -T`,
/// also in `$(…)`. Then it runs from where a subshell has moved to as well.
/// A signal the guard does not know, or one only known when it runs, counts
/// as one that is. `EXIT` and the ordinary signals are reset in a subshell.
pub(super) fn trap_inherited(args: &[Arg]) -> bool {
    let Some((_, signals)) = trap_operands(args) else {
        return false;
    };
    if signals.is_empty() {
        return true;
    }
    signals.iter().any(|signal| {
        let Some(name) = signal.known() else {
            return true;
        };
        let upper = name.to_ascii_uppercase();
        let name = upper.strip_prefix("SIG").unwrap_or(&upper);
        let real = name == "EXIT"
            || name.chars().all(|c| c.is_ascii_digit()) && !name.is_empty()
            || [
                "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "IOT", "BUS", "FPE", "KILL", "USR1",
                "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CLD", "CONT", "STOP",
                "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO",
                "POLL", "PWR", "SYS", "EMT", "INFO", "LOST", "THR", "LIBRT",
            ]
            .contains(&name)
            || name.starts_with("RTMIN")
            || name.starts_with("RTMAX");
        !real
    })
}

/// An interpreter runs code the guard does not read when it is given code inline
/// or reads it from its input; a script file or a module is its own
/// business. The flags that carry inline code differ per interpreter, so a
/// bundle (`-le`, `-Sc`) is read letter by letter: `-E` is code for perl
/// but an encoding for ruby.
pub(super) fn interpreter(key: &str, args: &[Arg]) -> Launch {
    let (short, long): (&[char], &[&str]) = if key.starts_with("python") {
        (&['c'], &[])
    } else {
        match key {
            "perl" => (&['e', 'E'], &[]),
            "ruby" => (&['e'], &["--eval"]),
            "node" | "nodejs" => (&['e', 'p'], &["--eval", "--print"]),
            "php" => (&['r', 'R', 'F'], &[]),
            "lua" => (&['e'], &[]),
            _ => (&['c', 'e'], &["--eval", "--print"]),
        }
    };
    let code = args.iter().any(|arg| {
        arg.known()
            .is_some_and(|text| match text.strip_prefix('-') {
                Some(bundle) if !bundle.is_empty() && !bundle.starts_with('-') => {
                    bundle.chars().any(|letter| short.contains(&letter))
                }
                _ => long.contains(&text),
            })
    });
    let file = args
        .iter()
        .any(|arg| !arg.known().is_some_and(|text| text.starts_with('-')));
    let stdin = args.iter().any(|arg| arg.known().is_some_and(is_stdin));
    // `perl -pi -e 's/a/b/' FILE` is an in-place edit like `sed -i`: its
    // files are judged as writes instead.
    if key == "perl" && perl_edits(args).is_some() {
        return Launch::Itself;
    }
    if code || stdin || !file {
        Launch::Reads(Reads::Interpreter)
    } else {
        Launch::Itself
    }
}

/// The files `perl -pi -e CODE FILE…` edits in place, when every piece of
/// `CODE` is a plain substitution or transliteration (`s/a/b/g`, `tr/a-z/A-Z/`)
/// that runs nothing; `None` for any other perl line.
pub(crate) fn perl_edits(args: &[Arg]) -> Option<Vec<&Arg>> {
    let mut in_place = false;
    let mut each_line = false;
    let mut codes = Vec::new();
    let mut files = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else {
            files.push(arg);
            continue;
        };
        if text == "-e" || text == "-E" {
            codes.push(iter.next()?.known()?);
        } else if text == "-I" || text == "-M" {
            iter.next();
        } else if let Some(bundle) = text.strip_prefix('-').filter(|b| !b.starts_with('-')) {
            if let Some(at) = bundle.find('i') {
                in_place = true;
                // `-i` takes the rest of the bundle as a backup suffix, so a
                // later `e` there is not `-e`.
                each_line |= bundle[..at].contains(['p', 'n']);
                continue;
            }
            each_line |= bundle.contains(['p', 'n']);
            if bundle.ends_with(['e', 'E']) {
                codes.push(iter.next()?.known()?);
            } else if bundle.contains(['e', 'E']) {
                return None;
            }
        } else {
            files.push(arg);
        }
    }
    let edits = in_place
        && each_line
        && !codes.is_empty()
        && codes.iter().all(|code| perl_code_edits(code));
    edits.then_some(files)
}

/// Whether perl code is only substitutions and transliterations whose
/// replacement runs nothing: no `/e` flag, no `@{[…]}` or `${…}`
/// interpolation, no backticks, no `system`/`exec`/`qx`.
fn perl_code_edits(code: &str) -> bool {
    if code.contains(['`'])
        || code.contains("@{")
        || code.contains("${")
        || ["system", "exec", "qx", "open", "unlink", "eval", "require"]
            .iter()
            .any(|word| code.contains(word))
    {
        return false;
    }
    code.split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .all(perl_substitution)
}

/// One `s/…/…/flags`, `tr/…/…/flags` or `y/…/…/flags` with a plain
/// delimiter and no `e` (evaluate) flag.
fn perl_substitution(statement: &str) -> bool {
    let rest = statement
        .strip_prefix("tr")
        .or_else(|| statement.strip_prefix('y'))
        .or_else(|| statement.strip_prefix('s'));
    let Some(rest) = rest else {
        return false;
    };
    let Some(delimiter) = rest.chars().next() else {
        return false;
    };
    if delimiter.is_alphanumeric() || delimiter.is_whitespace() || "{[(<\\".contains(delimiter) {
        return false;
    }
    let mut fields = 0;
    let mut escaped = false;
    let mut flags = None;
    for (at, c) in rest.char_indices().skip(1) {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == delimiter {
            fields += 1;
            if fields == 2 {
                flags = rest.get(at + c.len_utf8()..);
                break;
            }
        }
    }
    flags.is_some_and(|flags| flags.chars().all(|flag| "gimsxrdcaulnpo".contains(flag)))
}

/// The options of `bun` before its subcommand that take the next argument:
/// every one `bun --help` lists as `--option=<val>`, since bun also takes the
/// value as the next word. `--inspect` is left out, its value only follows `=`.
pub(crate) const BUN_VALUES: [&str; 46] = [
    "--cwd",
    "-c",
    "--config",
    "-r",
    "--preload",
    "--require",
    "--import",
    "--env-file",
    "--port",
    "-F",
    "--filter",
    "--elide-lines",
    "--shell",
    "--watch-kill-signal",
    "--cpu-prof-name",
    "--cpu-prof-dir",
    "--cpu-prof-interval",
    "--heap-prof-name",
    "--heap-prof-dir",
    "--heap-prof-interval",
    "--install",
    "--conditions",
    "--fetch-preconnect",
    "--max-http-header-size",
    "--dns-result-order",
    "--redirect-warnings",
    "--disable-warning",
    "--title",
    "--unhandled-rejections",
    "--console-depth",
    "--user-agent",
    "--cron-title",
    "--cron-period",
    "--main-fields",
    "--extension-order",
    "--tsconfig-override",
    "-d",
    "--define",
    "--drop",
    "--feature",
    "-l",
    "--loader",
    "--jsx-factory",
    "--jsx-fragment",
    "--jsx-import-source",
    "--jsx-runtime",
];

/// The options of `deno` and `deno run` that take the next argument. `--reload`
/// and `--env-file` are not among them: their value only follows `=`.
pub(crate) const DENO_VALUES: [&str; 10] = [
    "-c",
    "--config",
    "--import-map",
    "--lock",
    "--cert",
    "--location",
    "--seed",
    "--ext",
    "-L",
    "--log-level",
];

/// Whether `arg` is the program's own input, or a file standing for it.
pub(super) fn reads_input(arg: &Arg) -> bool {
    arg.known().is_some_and(is_stdin)
}

/// What `bun run file` and `deno run file` hand on: the arguments after the
/// `run` that follows the options (`bun --hot run file`); all of them when
/// there is no `run`.
pub(crate) fn after_run<'a>(args: &'a [Arg], values: &[&str]) -> &'a [Arg] {
    match after_options(args, values) {
        Some(at) if args[at].known() == Some("run") => &args[at + 1..],
        _ => args,
    }
}

/// `bun`: `-e`, `--eval`, `-p` and `--print` before the subcommand run code
/// given inline, as does `bun repl` and a script read from its input
/// (`bun run -`); `bun x` is a package runner; a file or a subcommand is its
/// own business.
pub(super) fn bun(unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    let first = after_options(args, &BUN_VALUES);
    let before = args.get(..first.unwrap_or(args.len())).unwrap_or_default();
    let eval = before.iter().filter_map(Arg::known).any(|text| {
        matches!(text, "-e" | "--eval" | "-p" | "--print")
            || text.starts_with("--eval=")
            || text.starts_with("--print=")
    });
    if eval {
        return Launch::Reads(Reads::Interpreter);
    }
    let Some(first) = first else {
        return Launch::Itself;
    };
    let Some(word) = args[first].known() else {
        return Launch::Itself;
    };
    match word {
        "x" => runner("bun", unit),
        "repl" => Launch::Reads(Reads::Interpreter),
        // `bun rimraf dir` runs the project's own delete tool by its name.
        name if DELETERS.contains(&name) => Launch::Replace(Box::new(running(unit, "bun", first))),
        "run" => match args
            .get(first + 1..)
            .and_then(|rest| after_options(rest, &BUN_VALUES))
            .map(|at| first + 1 + at)
        {
            Some(at) if reads_input(&args[at]) => Launch::Reads(Reads::Interpreter),
            Some(at)
                if args[at]
                    .known()
                    .is_some_and(|name| DELETERS.contains(&name)) =>
            {
                Launch::Replace(Box::new(running(unit, "bun", at)))
            }
            _ => Launch::Itself,
        },
        _ if is_stdin(word) => Launch::Reads(Reads::Interpreter),
        _ => Launch::Itself,
    }
}

/// `deno`: `deno eval` and `deno repl` run code given inline or read from
/// the input, as does `deno` alone and a script read from its input
/// (`deno run -`); `deno run npm:pkg` runs the package's program; a file or
/// another subcommand is its own business.
pub(super) fn deno(unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    let Some(first) = after_options(args, &DENO_VALUES) else {
        let prints = args
            .iter()
            .filter_map(Arg::known)
            .any(|text| matches!(text, "--version" | "-V" | "--help" | "-h"));
        return if prints {
            Launch::Itself
        } else {
            Launch::Reads(Reads::Interpreter)
        };
    };
    let Some(word) = args[first].known() else {
        return Launch::Reads(Reads::Interpreter);
    };
    match word {
        "eval" | "repl" => Launch::Reads(Reads::Interpreter),
        "run" => {
            let Some(at) = args
                .get(first + 1..)
                .and_then(|rest| after_options(rest, &DENO_VALUES))
                .map(|at| first + 1 + at)
            else {
                return Launch::Itself;
            };
            match args[at].known() {
                _ if reads_input(&args[at]) => Launch::Reads(Reads::Interpreter),
                Some(spec) if spec.starts_with("npm:") => {
                    let mut package = running(unit, "deno", at);
                    if let Arg::Known(text) = &package.program {
                        let name = text.trim_start_matches("npm:");
                        package.program = without_version(&Arg::Known(name.to_string()));
                    }
                    Launch::Replace(Box::new(package))
                }
                _ => Launch::Itself,
            }
        }
        _ if is_stdin(word) => Launch::Reads(Reads::Interpreter),
        _ => Launch::Itself,
    }
}
