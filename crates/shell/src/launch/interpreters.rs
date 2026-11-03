//! Shells and interpreters given a script, inline code, or their input:
//! which is which, and the perl in-place edits read like `sed -i`.

use super::wrappers::{runner, running, running_package, DELETERS};
use super::{after_options, is_stdin, join, Launch};
use crate::inline;
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

/// The options of the interpreter `key` that carry code to run, by letter
/// and by long name: `perl -e`, `python3 -c`, `node -p`, `php -r`.
pub(crate) fn code_options(key: &str) -> (&'static [char], &'static [&'static str]) {
    if key.starts_with("python") {
        return (&['c'], &[]);
    }
    match key {
        "perl" => (&['e', 'E'], &[]),
        "ruby" => (&['e'], &["--eval"]),
        "node" | "nodejs" => (&['e', 'p'], &["--eval", "--print"]),
        "php" => (&['r', 'R', 'F'], &[]),
        "lua" => (&['e'], &[]),
        _ => (&['c', 'e'], &["--eval", "--print"]),
    }
}

/// The short options of the interpreter `key` that take a value which is
/// neither code nor a file it reads, and so end a bundle: python's `-W
/// ignore`, php's `-d foo=1`, perl's `-I lib`.
pub(crate) fn valued_options(key: &str) -> &'static [char] {
    if key.starts_with("python") {
        return &['W', 'X', 'm', 'Q'];
    }
    match key {
        "perl" => &['I', 'M', 'm'],
        "ruby" => &['I', 'r', 'C', 'E', 'K'],
        "node" | "nodejs" => &['r', 'C'],
        "php" => &['c', 'd', 'z', 't', 'B', 'E'],
        "lua" => &['l'],
        _ => &[],
    }
}

/// An interpreter runs code the guard does not read when it is given code inline
/// or reads it from its input; a script file or a module is its own
/// business. The flags that carry inline code differ per interpreter, so a
/// bundle (`-le`, `-Sc`) is read letter by letter: `-E` is code for perl
/// but an encoding for ruby. `console` is whether a line with nothing to run
/// reads its input: always under a POSIX shell, and under cmd and PowerShell
/// only when something is piped into it.
pub(super) fn interpreter(key: &str, args: &[Arg], console: bool) -> Launch {
    let (short, long) = code_options(key);
    let code = args.iter().any(|arg| {
        arg.known()
            .is_some_and(|text| match text.strip_prefix('-') {
                Some(bundle) if !bundle.is_empty() && !bundle.starts_with('-') => {
                    bundle.chars().any(|letter| short.contains(&letter))
                }
                _ => long.contains(&text),
            })
    });
    // Code in a `data:` URL that node loads first runs, and is not read.
    let code = code || (matches!(key, "node" | "nodejs") && inline::loads_foreign_code(args));
    let file = args
        .iter()
        .any(|arg| !arg.known().is_some_and(|text| text.starts_with('-')));
    let stdin = args.iter().any(|arg| arg.known().is_some_and(is_stdin));
    // Inline Python and JavaScript are read, not left to the caller.
    if let (Some(language), Some(source)) = (inline::language(key), inline::code(key, args)) {
        return Launch::Inline(language, source);
    }
    // `perl -pi -e 's/a/b/' FILE` is an in-place edit like `sed -i`: its
    // files are judged as writes instead.
    if key == "perl" && perl_edits(args).is_some() {
        return Launch::Itself;
    }
    // `python3 --version` prints and exits: it reads no input.
    if !code && !stdin && !file && inline::prints(key, args) {
        return Launch::Itself;
    }
    // Nothing to run reads the input (the REPL) where there is one to read.
    if code || stdin || (!file && console) {
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
/// the ones `bun --help` lists as `--option=<val>` that bun also gives the
/// next word as their value. `-c` and `--config` and `--inspect` are left
/// out, their value only follows `=` (`bun -c rimraf a` runs `rimraf`).
///
/// This is the guard's reading of the options, and bun's own is different:
/// bun takes the first word that does not start with a dash as its
/// subcommand, before any option reads its value (`bun -F x echo` runs
/// `bunx echo`). [`bun_launch`] judges that subcommand as well.
pub(crate) const BUN_VALUES: [&str; 44] = [
    "--cwd",
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

/// The options of `deno` and `deno run` that take the next argument, from
/// deno's own option definitions (`libs/cli_parser/src/defs.rs`); every one
/// takes exactly one value. `--reload` and `--env-file` are not among them:
/// their value only follows `=`.
pub(crate) const DENO_VALUES: [&str; 20] = [
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
    "--preload",
    "--import",
    "--require",
    "--conditions",
    "--min-dep-age",
    "--minimum-dependency-age",
    "--cpu-prof-dir",
    "--cpu-prof-name",
    "--cpu-prof-interval",
    "--inspect-publish-uid",
];

/// Whether `arg` is the program's own input, or a file standing for it.
pub(super) fn reads_input(arg: &Arg) -> bool {
    arg.known().is_some_and(is_stdin)
}

/// What `bun run file` and `deno run file` hand on: the arguments after the
/// `run` that follows the options (`bun --hot run file`), or after deno's
/// `watch`, which is `run --hmr`; all of them when there is no `run`.
pub(crate) fn after_run<'a>(key: &str, args: &'a [Arg]) -> &'a [Arg] {
    let (values, words): (&[&str], &[&str]) = if key == "bun" {
        (&BUN_VALUES, &["run"])
    } else {
        (&DENO_VALUES, &["run", "watch"])
    };
    match after_options(args, values) {
        Some(at) if args[at].known().is_some_and(|word| words.contains(&word)) => &args[at + 1..],
        _ => args,
    }
}

/// Whether a short word before bun's subcommand carries inline code: `-e`
/// or `-p` with the code next or attached (`-e'code'`), also in a bundle of
/// short options (`-pe`, `-bp`). A short option that takes a value ends the
/// bundle: the rest of the word is its value (`-dNODE_ENV=x`, and `-ce` takes
/// `e` as the config file: `-c` and `--config` stand out of [`BUN_VALUES`]
/// because bun finds its subcommand before it reads a value).
fn bun_inline(text: &str) -> bool {
    let Some(bundle) = text
        .strip_prefix('-')
        .filter(|bundle| !bundle.starts_with('-'))
    else {
        return false;
    };
    for letter in bundle.chars() {
        match letter {
            'e' | 'p' => return true,
            'c' | 'r' | 'F' | 'd' | 'l' => return false,
            _ => {}
        }
    }
    false
}

/// `bun`: `-e`, `--eval`, `-p` and `--print` before the subcommand run code
/// given inline (also in a bundle, `-pe`, or with the code attached,
/// `-e'code'`), as does `bun repl` and a script read from its input
/// (`bun run -`); `bun x` is a package runner; `bun exec` runs its
/// arguments as a shell script; a file or a subcommand is its own business.
pub(super) fn bun(unit: &Unit) -> Launch {
    let evals = unit.args.iter().filter_map(Arg::known).any(bun_evals);
    // `bun run -e CODE` is `bun -e CODE`: the code is read without the
    // subcommand in front of it. `bun run` loads `.env` first, so the code
    // is not all bun is given.
    let mut args = unit.args.clone();
    let mut run = false;
    if let Some(first) = after_options(&args, &BUN_VALUES) {
        if args[first].known() == Some("run") {
            args.remove(first);
            run = true;
        }
    }
    let launch = match with_code("bun", &args, bun_launch(unit)) {
        Launch::Inline(language, code) if run => Launch::Inline(
            language,
            inline::Code {
                plain: false,
                ..code
            },
        ),
        launch => launch,
    };
    only_runs(unit, evals, launch)
}

/// A `bun` or `deno` line that reads inline code (`bun -e CODE`, `deno eval
/// CODE`) runs the code the guard reads, as it does for node and python;
/// when the arguments do not say where the code is, the line reads its
/// input as it did. `args` are the line's, with the code where `key` reads
/// it.
fn with_code(key: &str, args: &[Arg], launch: Launch) -> Launch {
    match (&launch, inline::code(key, args)) {
        (Launch::Reads(Reads::Interpreter), Some(code)) => {
            Launch::Inline(inline::Language::JavaScript, code)
        }
        _ => launch,
    }
}

/// The REPL of `bun repl`, `deno repl` and a bare `deno`: it reads its input
/// under a POSIX shell, and under cmd and PowerShell only when something is
/// piped into it.
fn repl(unit: &Unit) -> Launch {
    if unit.shell == Shell::Posix || super::piped(unit) {
        Launch::Reads(Reads::Interpreter)
    } else {
        Launch::Itself
    }
}

/// A line for cmd reads the parts of `bun` and `deno` that start a program
/// (a package runner, a delete tool, an npm specifier, `bun run name`), and
/// not what it reads of a POSIX shell, which cmd lines do not get. Inline
/// code and what is piped into the program are not read there either, which
/// comes back as `unknown`. `evals` is whether the line carries a flag that
/// runs inline code: when the code itself cannot be told (a module the
/// options load, a subcommand in between), the line still runs code the
/// guard does not read, and stays `unknown` in cmd as it is in the others.
fn only_runs(unit: &Unit, evals: bool, launch: Launch) -> Launch {
    match launch {
        Launch::Replace(_) | Launch::Inline(..) => launch,
        Launch::Either(first, second) => Launch::Either(
            Box::new(only_runs(unit, evals, *first)),
            Box::new(only_runs(unit, evals, *second)),
        ),
        _ if unit.shell != Shell::Cmd => launch,
        Launch::Reads(_) if evals || super::piped(unit) => launch,
        _ => Launch::Itself,
    }
}

/// Whether the option `text` makes bun run the code that follows it.
fn bun_evals(text: &str) -> bool {
    matches!(text, "--eval" | "--print")
        || text.starts_with("--eval=")
        || text.starts_with("--print=")
        || bun_inline(text)
}

/// `bun` read by the guard's options and by bun's own subcommand, the first
/// word that does not start with a dash.
fn bun_launch(unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    let first = after_options(args, &BUN_VALUES);
    let before = args.get(..first.unwrap_or(args.len())).unwrap_or_default();
    if before.iter().filter_map(Arg::known).any(bun_evals) {
        return Launch::Reads(Reads::Interpreter);
    }
    let by_value = first.map_or(Launch::Itself, |at| bun_subcommand(unit, at));
    // Bun itself takes the first word that does not start with a dash as the
    // subcommand, before any option reads its value (`bun -F x echo` runs
    // `bunx echo`, `bun --title repl` opens the REPL). The options that take
    // a value are skipped above, so when the two readings differ and bun's
    // is one that starts a program, both are judged and the riskier counts.
    let Some(plain) = after_options(args, &[]).filter(|plain| Some(*plain) != first) else {
        return by_value;
    };
    let starts_one = args[plain].known().is_some_and(|word| {
        matches!(word, "x" | "run" | "exec" | "repl") || DELETERS.contains(&word)
    });
    if !starts_one {
        return by_value;
    }
    let by_bun = bun_subcommand(unit, plain);
    match (by_value, by_bun) {
        (Launch::Itself, other) | (other, Launch::Itself) => other,
        // Two readings that come to the same are judged once.
        (value, bun) if value == bun => value,
        (value, bun) => Launch::Either(Box::new(value), Box::new(bun)),
    }
}

/// What the subcommand of `bun` at `first` does.
fn bun_subcommand(unit: &Unit, first: usize) -> Launch {
    let args = unit.args.as_slice();
    let Some(word) = args[first].known() else {
        return Launch::Itself;
    };
    match word {
        "x" => runner("bun", unit),
        "repl" => repl(unit),
        // `bun exec 'script'` runs a shell script (bun's own shell, which
        // reads POSIX), its options standing before the script too.
        "exec" => {
            let rest = &args[first + 1..];
            after_options(rest, &BUN_VALUES).map_or(Launch::Itself, |at| {
                Launch::Script(Shell::Posix, join(&rest[at..]))
            })
        }
        // `bun rimraf dir` runs the project's own delete tool by its name.
        name if DELETERS.contains(&name) => Launch::Replace(Box::new(running(unit, "bun", first))),
        // `bun run name` runs a script of the project, a bin of it, or else
        // any program on the path (`bun run rm -rf x` deletes): a word that
        // is no file is judged as the program.
        "run" => match args
            .get(first + 1..)
            .and_then(|rest| after_options(rest, &BUN_VALUES))
            .map(|at| first + 1 + at)
        {
            // A code flag among the options of `run` (`bun -F x run -e
            // CODE`) is code given inline, read as `bun -e CODE` is.
            Some(at)
                if args[first + 1..at]
                    .iter()
                    .filter_map(Arg::known)
                    .any(bun_evals) =>
            {
                Launch::Reads(Reads::Interpreter)
            }
            Some(at) if reads_input(&args[at]) => Launch::Reads(Reads::Interpreter),
            Some(at) if !is_file(&args[at]) => Launch::Replace(Box::new(running(unit, "bun", at))),
            _ => Launch::Itself,
        },
        _ if is_stdin(word) => Launch::Reads(Reads::Interpreter),
        _ => Launch::Itself,
    }
}

/// Whether the word `bun run` is given names a file: it has a folder in it or
/// an extension (`./build.ts`, `src/main`, `build.ts`). A word only known when
/// the line runs is not known to be one.
fn is_file(arg: &Arg) -> bool {
    arg.known().is_some_and(|text| {
        text.contains(['/', '\\']) || std::path::Path::new(text).extension().is_some()
    })
}

/// `deno`: `deno eval` and `deno repl` run code given inline or read from
/// the input, as does `deno` alone and a script read from its input
/// (`deno run -`); `deno run npm:pkg` runs the package's program, and so do
/// `deno watch` (which is `run --hmr`) and `deno` with no subcommand (its
/// default is `run`: `deno npm:pkg`); `deno x` is a package runner; a file or
/// another subcommand is its own business.
pub(super) fn deno(unit: &Unit) -> Launch {
    only_runs(
        unit,
        false,
        with_code("deno", &unit.args, deno_launch(unit)),
    )
}

fn deno_launch(unit: &Unit) -> Launch {
    let args = unit.args.as_slice();
    let Some(first) = after_options(args, &DENO_VALUES) else {
        let prints = args.iter().filter_map(Arg::known).any(|text| {
            matches!(text, "--version" | "-V" | "-v" | "--help" | "-h")
                || text.starts_with("--help=")
        });
        return if prints { Launch::Itself } else { repl(unit) };
    };
    let Some(word) = args[first].known() else {
        return Launch::Reads(Reads::Interpreter);
    };
    match word {
        "eval" => Launch::Reads(Reads::Interpreter),
        "repl" => repl(unit),
        "x" => runner("deno", unit),
        // `deno task --eval 'cmd'` runs its words as a line of deno's own
        // shell, which reads POSIX.
        "task" => {
            let rest = &args[first + 1..];
            match after_options(rest, &DENO_TASK_VALUES) {
                Some(at)
                    if rest[..at]
                        .iter()
                        .filter_map(Arg::known)
                        .any(|text| text == "--eval") =>
                {
                    Launch::Script(Shell::Posix, join(&rest[at..]))
                }
                _ => Launch::Itself,
            }
        }
        "run" | "watch" => args
            .get(first + 1..)
            .and_then(|rest| after_options(rest, &DENO_VALUES))
            .map_or(Launch::Itself, |at| deno_target(unit, first + 1 + at)),
        _ => deno_target(unit, first),
    }
}

/// The options of `deno task` that take the next word.
const DENO_TASK_VALUES: [&str; 5] = ["--cwd", "-c", "--config", "-f", "--filter"];

/// What `deno run` does with the script at `at`: its input is read as code,
/// an npm specifier is a package whose program runs, a file is its own
/// business.
fn deno_target(unit: &Unit, at: usize) -> Launch {
    let arg = &unit.args[at];
    match arg.known() {
        _ if reads_input(arg) => Launch::Reads(Reads::Interpreter),
        Some(spec) if spec.starts_with("npm:") => {
            Launch::Replace(Box::new(running_package(unit, "deno", at)))
        }
        _ => Launch::Itself,
    }
}
