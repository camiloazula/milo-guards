//! Shells and interpreters given a script, inline code, or their input:
//! which is which, and the perl in-place edits read like `sed -i`.

use super::wrappers::{runner, runner_in, running, running_package, DELETERS};
use super::{after_options, after_options_by, is_stdin, join, Launch, Word};
use crate::inline;
use crate::unit::{Arg, Reads, Unit};
use crate::Shell;

/// The POSIX shells, which run a script with `-c` or read one from their
/// input.
pub(crate) const SHELLS: [&str; 11] = [
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "csh", "tcsh",
];

/// Language interpreters that read code from their input when given no
/// script: besides python (and the other names of a Python, by
/// [`is_interpreter`]) and node, the Python launcher `py`, `pypy`, `ipython`,
/// and the TypeScript runners `tsx` and `ts-node`, which take node's options.
pub(crate) const INTERPRETERS: [&str; 17] = [
    "python", "python2", "python3", "py", "pypy", "pypy3", "ipython", "perl", "ruby", "node",
    "nodejs", "tsx", "ts-node", "php", "lua", "bun", "deno",
];

/// Whether `key` is the interpreter named in [`INTERPRETERS`] or one of its
/// other names: a Python of a version (`python3.12`, `pypy3.10`,
/// `ipython3`), `graalpy` and `micropython`, and the other programs of ts-node
/// (`ts-node-esm`, `ts-node-script`).
pub(crate) fn is_interpreter(key: &str) -> bool {
    INTERPRETERS.contains(&key)
        || ["python", "pypy", "ipython", "graalpy", "micropython"]
            .iter()
            .any(|name| versioned(key, name))
        || is_ts_node(key)
}

/// Whether `key` is `name`, or `name` and a version (`python3.12`,
/// `pypy3.10`, `ipython3`).
fn versioned(key: &str, name: &str) -> bool {
    key.strip_prefix(name).is_some_and(|version| {
        version.is_empty()
            || (version.starts_with(|c: char| c.is_ascii_digit())
                && version.chars().all(|c| c.is_ascii_digit() || c == '.'))
    })
}

/// Whether the interpreter `key` runs Python, and reads python's options.
pub(crate) fn is_python(key: &str) -> bool {
    key.starts_with("python")
        || key == "py"
        || ["pypy", "ipython", "graalpy", "micropython"]
            .iter()
            .any(|name| versioned(key, name))
}

/// Whether the interpreter `key` is `ipython` (also `ipython3`), whose
/// own options are not python's.
pub(crate) fn is_ipython(key: &str) -> bool {
    versioned(key, "ipython")
}

/// Whether `key` is ts-node, by any of the names of its programs.
pub(crate) fn is_ts_node(key: &str) -> bool {
    matches!(
        key,
        "ts-node"
            | "ts-node-esm"
            | "ts-node-script"
            | "ts-node-cwd"
            | "ts-node-transpile-only"
            | "ts-script"
    )
}

/// Whether the interpreter `key` is node, or a runner of TypeScript built on
/// it that reads node's options (`tsx`, `ts-node`).
pub(crate) fn is_node(key: &str) -> bool {
    matches!(key, "node" | "nodejs" | "tsx") || is_ts_node(key)
}

/// The arguments the interpreter `key` reads as its own options: all of
/// them, but for the Python launcher `py`, whose first word may pick the
/// Python it starts (`-3`, `-3.12`, `-3.12-64`, `-V:3.12`), which reads the
/// rest. PowerShell reads `-3` as a number, a word it computes: as written,
/// it is the same word.
pub(crate) fn own_args<'a>(key: &str, args: &'a [Arg]) -> &'a [Arg] {
    match args.split_first() {
        Some((first, rest)) if key == "py" && picks_python(first.text()) => rest,
        _ => args,
    }
}

/// Whether `text`, the first word of `py`, picks the Python it runs.
fn picks_python(text: &str) -> bool {
    if text.starts_with("-V:") || text.starts_with("--version:") {
        return true;
    }
    text.strip_prefix('-').is_some_and(|version| {
        version.starts_with(|c: char| c.is_ascii_digit())
            && version
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
    })
}

/// The Python `py` starts is Python 3 when its first word says so (`-3`,
/// `-3.12`, `-V:3.12`); otherwise it is the default its own settings name.
pub(crate) fn py_picks_three(args: &[Arg]) -> bool {
    args.first()
        .map(Arg::text)
        .filter(|text| picks_python(text))
        .is_some_and(|text| {
            text.trim_start_matches('-')
                .trim_start_matches("V:")
                .trim_start_matches("version:")
                .starts_with('3')
        })
}

/// Whether `py` is only asked to list the Pythons it knows (`-0`, `-0p`,
/// `--list`, `--list-paths`), which runs none.
fn py_lists(args: &[Arg]) -> bool {
    matches!(
        args.first().and_then(Arg::known),
        Some("-0" | "-0p" | "--list" | "--list-paths")
    )
}

/// A POSIX shell: `-c` runs its first operand; a script file is its own
/// business; `--version` and `--help` print; with none of them, it reads
/// commands from its input.
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
            // `bash --version` prints and runs nothing.
            "--version" | "--help" if !command && !stdin => return Launch::Itself,
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
    if is_python(key) {
        return (&['c'], &[]);
    }
    if is_node(key) {
        return (&['e', 'p'], &["--eval", "--print"]);
    }
    match key {
        "perl" => (&['e', 'E'], &[]),
        "ruby" => (&['e'], &["--eval"]),
        "php" => (&['r', 'R', 'F'], &[]),
        "lua" => (&['e'], &[]),
        _ => (&['c', 'e'], &["--eval", "--print"]),
    }
}

/// The short options of the interpreter `key` that take a value which is
/// neither code nor a file it reads, and so end a bundle: python's `-W
/// ignore`, php's `-d foo=1`, perl's `-I lib`.
pub(crate) fn valued_options(key: &str) -> &'static [char] {
    if is_python(key) {
        return &['W', 'X', 'm', 'Q'];
    }
    match key {
        "perl" => &['I', 'M', 'm'],
        "ruby" => &['I', 'r', 'C', 'E', 'K'],
        // `-P tsconfig.json`, `-O '{…}'`, `-C ttypescript`, `-I`, `-D`.
        key if is_ts_node(key) => &['r', 'C', 'P', 'O', 'I', 'D'],
        "node" | "nodejs" | "tsx" => &['r', 'C'],
        "php" => &['c', 'd', 'z', 't', 'B', 'E', 'S', 'f'],
        "lua" => &['l'],
        _ => &[],
    }
}

/// How an interpreter reads its options, besides the ones that carry code
/// ([`code_options`]) and the short ones that take a value
/// ([`valued_options`]).
struct Table {
    /// Short options that take the rest of their word as a value, and never
    /// the next word: perl's `-i.bak`, `-0777`, `-l`, ruby's `-W2`.
    attached: &'static [char],
    /// Long options, without their dashes, that take the next word as their
    /// value when no `=` gives it one.
    long_values: &'static [&'static str],
    /// Whether every long option is in the table or an error: python, perl,
    /// ruby, php and lua. Node also passes any option it does not know to V8,
    /// whose options with a value take the next word too.
    strict: bool,
    /// The short option that asks for code from the input once the script
    /// has run (`python3 -i x.py`, `node -i`, `lua -i`).
    interactive: Option<char>,
    /// The short option that names the module to run in place of a script
    /// (`python3 -m pytest`), or the script itself (php's `-f x.php`).
    names_script: Option<char>,
    /// The long options known to run nothing, when every other may run code:
    /// `ipython` reads any `--Class.trait=value` as a setting, and
    /// `--InteractiveShellApp.code_to_run`, `exec_lines`, `exec_files` and
    /// `--ext` run code before the script.
    harmless_long: Option<&'static [&'static str]>,
}

/// `ipython`'s long options that take the next word as their value.
const IPYTHON_VALUES: [&str; 13] = [
    "profile",
    "profile-dir",
    "ipython-dir",
    "config",
    "logfile",
    "logappend",
    "log-level",
    "colors",
    "gui",
    "pylab",
    "matplotlib",
    "autocall",
    "cache-size",
];

/// `ipython`'s long options that run nothing: its flags, and the ones that
/// take a value ([`IPYTHON_VALUES`]).
const IPYTHON_HARMLESS: [&str; 46] = [
    "help",
    "help-all",
    "version",
    "banner",
    "no-banner",
    "quick",
    "classic",
    "simple-prompt",
    "no-simple-prompt",
    "nosep",
    "pprint",
    "no-pprint",
    "color-info",
    "no-color-info",
    "autoindent",
    "no-autoindent",
    "automagic",
    "no-automagic",
    "confirm-exit",
    "no-confirm-exit",
    "term-title",
    "no-term-title",
    "quiet",
    "debug",
    "init",
    "pdb",
    "no-pdb",
    "autoedit-syntax",
    "no-autoedit-syntax",
    "tip",
    "no-tip",
    "show-config",
    "show-config-json",
    "profile",
    "profile-dir",
    "ipython-dir",
    "config",
    "logfile",
    "logappend",
    "log-level",
    "colors",
    "gui",
    "pylab",
    "matplotlib",
    "autocall",
    "cache-size",
];

/// Node's long options that take the next word as their value, from its
/// documentation (`node --help`), with those of the TypeScript runners on
/// top of it.
const NODE_VALUES: [&str; 58] = [
    "require",
    "import",
    "loader",
    "experimental-loader",
    "conditions",
    "input-type",
    "env-file",
    "env-file-if-exists",
    "title",
    "inspect-port",
    "debug-port",
    "redirect-warnings",
    "disable-warning",
    "diagnostic-dir",
    "report-dir",
    "report-directory",
    "report-filename",
    "report-signal",
    "icu-data-dir",
    "openssl-config",
    "secure-heap",
    "secure-heap-min",
    "heapsnapshot-signal",
    "heapsnapshot-near-heap-limit",
    "cpu-prof-dir",
    "cpu-prof-name",
    "cpu-prof-interval",
    "heap-prof-dir",
    "heap-prof-name",
    "heap-prof-interval",
    "watch-path",
    "watch-kill-signal",
    "test-reporter",
    "test-reporter-destination",
    "test-name-pattern",
    "test-skip-pattern",
    "test-concurrency",
    "test-timeout",
    "test-shard",
    "unhandled-rejections",
    "trace-event-categories",
    "trace-event-file-pattern",
    "tls-cipher-list",
    "tls-keylog",
    "use-largepages",
    "max-http-header-size",
    "dns-result-order",
    "experimental-config-file",
    "localstorage-file",
    "snapshot-blob",
    "allow-fs-read",
    "allow-fs-write",
    // `tsx --tsconfig`; ts-node's own.
    "tsconfig",
    "project",
    "compiler",
    "compiler-options",
    "ignore-diagnostics",
    "scope-dir",
];

/// The options table of the interpreter `key`.
fn table(key: &str) -> Table {
    let plain = Table {
        attached: &[],
        long_values: &[],
        strict: true,
        interactive: None,
        names_script: None,
        harmless_long: None,
    };
    if is_ipython(key) {
        return Table {
            long_values: &IPYTHON_VALUES,
            interactive: Some('i'),
            names_script: Some('m'),
            harmless_long: Some(&IPYTHON_HARMLESS),
            ..plain
        };
    }
    if is_python(key) {
        return Table {
            long_values: &["check-hash-based-pycs"],
            interactive: Some('i'),
            names_script: Some('m'),
            ..plain
        };
    }
    if is_node(key) {
        return Table {
            long_values: &NODE_VALUES,
            strict: false,
            interactive: Some('i'),
            ..plain
        };
    }
    match key {
        "perl" => Table {
            attached: &['0', 'l', 'i', 'x', 'd', 'D', 'C', 'F', 'V'],
            ..plain
        },
        "ruby" => Table {
            attached: &['0', 'i', 'W', 'x', 'T', 'F'],
            long_values: &[
                "enable",
                "disable",
                "encoding",
                "external-encoding",
                "internal-encoding",
                "dump",
                "backtrace-limit",
                "crash-report",
                "parser",
            ],
            ..plain
        },
        "php" => Table {
            long_values: &[
                "php-ini",
                "define",
                "zend-extension",
                "file",
                "rf",
                "rc",
                "re",
                "rz",
                "ri",
            ],
            names_script: Some('f'),
            ..plain
        },
        "lua" => Table {
            interactive: Some('i'),
            ..plain
        },
        _ => Table {
            strict: false,
            ..plain
        },
    }
}

/// What an interpreter's options say, read with its own table of the
/// options that take a value: the word after one is its value, never the
/// script.
#[derive(Default)]
pub(crate) struct Options {
    /// Where the script is: the first word that is not an option, or the
    /// value of php's `-f`. A word only known when it runs there may be an
    /// option too; it is where the script is all the same.
    pub(crate) script: Option<usize>,
    /// The module python's `-m` runs in place of a script, and where its
    /// own arguments start.
    pub(crate) module: Option<(Arg, usize)>,
    /// Whether the interpreter reads code from its input once the script has
    /// run (`-i`).
    pub(crate) interactive: bool,
    /// Whether a long option the table does not know stands right before the
    /// script, with no `=` (`node --stack-size 100 x.js`): it may have taken
    /// the script as its value.
    pub(crate) unsure: bool,
    /// Whether a long option the interpreter may run code by stands before
    /// the script (`ipython`'s `--InteractiveShellApp.exec_lines=…`, `--ext`).
    pub(crate) runs_code: bool,
    /// The files loaded before the script, code that runs as the script
    /// does: the modules node and the runners built on it load (`-r`,
    /// `--require`, `--import`, `--loader`, `--experimental-loader`), and the
    /// files php's `-d auto_prepend_file=` and `auto_append_file=` name.
    pub(crate) preloads: Vec<Arg>,
    /// The libraries ruby's `-r` and perl's `-M` and `-m` load by name
    /// before the script, looked up in [`Options::includes`] (and as a path
    /// by ruby, when one starts with `./`): `-r s` is `s.rb`, `-MFoo::Bar`
    /// is `Foo/Bar.pm`.
    pub(crate) requires: Vec<Arg>,
    /// The folders ruby's and perl's `-I` put first where a library is
    /// looked up.
    pub(crate) includes: Vec<Arg>,
}

impl Options {
    /// Note the value of the short option `letter` of `key` (one that takes
    /// a value, [`valued_options`]) when it loads code before the script or
    /// names where a library is looked up.
    fn short_value(&mut self, key: &str, letter: char, value: Arg) {
        match (key, letter) {
            (key, 'r') if is_node(key) => self.preloads.push(value),
            ("ruby", 'r') | ("perl", 'M' | 'm') => self.requires.push(value),
            ("ruby" | "perl", 'I') => self.includes.push(value),
            ("php", 'd') => self.php_setting(&value),
            _ => {}
        }
    }

    /// php's `-d NAME=VALUE`: `auto_prepend_file` and `auto_append_file`
    /// name a file php runs before and after the script.
    fn php_setting(&mut self, value: &Arg) {
        let Some((name, file)) = value.known().and_then(|text| text.split_once('=')) else {
            return;
        };
        if matches!(name.trim(), "auto_prepend_file" | "auto_append_file") {
            let file = file.trim().trim_matches(['"', '\'']);
            if !file.is_empty() {
                self.preloads.push(Arg::Known(file.to_string()));
            }
        }
    }
}

/// Read the options of the interpreter `key`, its own arguments (see
/// [`own_args`]), up to the script, the module, or the code it is given.
pub(crate) fn options(key: &str, args: &[Arg]) -> Options {
    let (code_short, code_long) = code_options(key);
    let valued = valued_options(key);
    let table = table(key);
    let node = is_node(key);
    let mut found = Options::default();
    // Whether the word before is a long option the table does not know.
    let mut unknown_before = false;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            found.script = Some(at);
            break;
        };
        if text == "--" {
            found.script = (at + 1 < args.len()).then_some(at + 1);
            break;
        }
        if text == "-" || code_long.contains(&text) {
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            // Node reads an underscore in an option's name as a hyphen.
            let name = if node {
                name.replace('_', "-")
            } else {
                name.to_string()
            };
            if code_long
                .iter()
                .any(|code| code.get(2..) == Some(name.as_str()))
            {
                break;
            }
            unknown_before = false;
            if table
                .harmless_long
                .is_some_and(|harmless| !harmless.contains(&name.as_str()))
            {
                found.runs_code = true;
                return found;
            }
            if node && name == "interactive" {
                found.interactive = true;
            } else if value.is_none() && table.long_values.contains(&name.as_str()) {
                if node && preloads(&name) {
                    found.preloads.extend(args.get(at + 1).cloned());
                }
                if key == "php" && name == "define" {
                    if let Some(next) = args.get(at + 1) {
                        found.php_setting(next);
                    }
                }
                if key == "php" && name == "file" {
                    found.script = (at + 1 < args.len()).then_some(at + 1);
                    break;
                }
                at += 1;
            } else if let (true, Some(value)) = (node && preloads(&name), value) {
                found.preloads.push(Arg::Known(value.to_string()));
            } else if let (true, Some(value)) = (key == "php" && name == "define", value) {
                found.php_setting(&Arg::Known(value.to_string()));
            } else {
                unknown_before = value.is_none() && !table.strict;
            }
            at += 1;
            continue;
        }
        let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty()) else {
            found.script = Some(at);
            found.unsure = unknown_before;
            break;
        };
        unknown_before = false;
        let mut skip = 0;
        for (index, letter) in bundle.char_indices() {
            let rest = &bundle[index + letter.len_utf8()..];
            if code_short.contains(&letter) {
                return found;
            }
            if table.interactive == Some(letter) {
                found.interactive = true;
            }
            if table.names_script == Some(letter) {
                if rest.is_empty() {
                    let next = (at + 1 < args.len()).then_some(at + 1);
                    if letter == 'm' {
                        found.module = next.map(|next| (args[next].clone(), next + 1));
                    } else {
                        found.script = next;
                    }
                } else if letter == 'm' {
                    found.module = Some((Arg::Known(rest.to_string()), at + 1));
                } else {
                    found.script = Some(at);
                }
                return found;
            }
            if valued.contains(&letter) {
                let value = if rest.is_empty() {
                    skip = 1;
                    args.get(at + 1).cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
                };
                if let Some(value) = value {
                    found.short_value(key, letter, value);
                }
                break;
            }
            if table.attached.contains(&letter) {
                break;
            }
        }
        at += 1 + skip;
    }
    found
}

/// Whether node's long option `name` loads a module before the script.
fn preloads(name: &str) -> bool {
    matches!(
        name,
        "require" | "import" | "loader" | "experimental-loader"
    )
}

/// The modules python's `-m` runs that run what they are given: the code
/// `timeit` times, the script `cProfile`, `profile` and `trace` run under
/// them, and the input `pdb` and `code` read.
/// The REPLs `asyncio`, `IPython`, `bpython` and `ptpython` read code from
/// the input as `code` does.
const RUNS_GIVEN: [&str; 10] = [
    "timeit", "cProfile", "profile", "pdb", "trace", "code", "asyncio", "IPython", "bpython",
    "ptpython",
];

/// An interpreter runs code the guard does not read when it is given code inline
/// or reads it from its input; a script file or a module is its own
/// business. The flags that carry inline code differ per interpreter, so a
/// bundle (`-le`, `-Sc`) is read letter by letter: `-E` is code for perl
/// but an encoding for ruby. Where the script is, is read with the
/// interpreter's own table of the options that take a value ([`options`]):
/// `perl -I lib` has no script, so it reads its input. `posix` is whether the
/// line is a POSIX shell's and `input` whether the interpreter is handed an
/// input (something piped into it, a file redirected onto it): a line with
/// nothing to run reads its input always under a POSIX shell, and under cmd
/// and PowerShell only when it is handed one.
pub(super) fn interpreter(key: &str, args: &[Arg], posix: bool, input: bool) -> Launch {
    let console = posix || input;
    // `py -0` lists the Pythons it knows; `py -3 …` runs Python 3 with the
    // rest.
    if key == "py" && py_lists(args) {
        return Launch::Itself;
    }
    let args = own_args(key, args);
    let (short, long) = code_options(key);
    let read = options(key, args);
    // CPython's words after the script or the module are its own
    // arguments, not the interpreter's: `python3 -m zipfile -c a.zip src`
    // makes an archive. Its table names every option that takes a value,
    // and it refuses one it does not know. Not so for the others that read
    // python's options: IPython reads its own options after the file (`-c`
    // there runs code), and PyPy has long options the table does not know
    // that take a value (`--jit off`), so every word of theirs is read.
    let cpython = key.starts_with("python") || key == "py";
    let end = read
        .script
        .or(read.module.as_ref().map(|(_, own)| *own))
        .filter(|_| cpython && !read.unsure)
        .unwrap_or(args.len());
    let code = args.get(..end).unwrap_or(args).iter().any(|arg| {
        arg.known()
            .is_some_and(|text| match text.strip_prefix('-') {
                Some(bundle) if !bundle.is_empty() && !bundle.starts_with('-') => {
                    bundle.chars().any(|letter| short.contains(&letter))
                }
                _ => long.contains(&text),
            })
    });
    // Code in a `data:` URL that node loads first runs, and is not read.
    let code = code || (is_node(key) && inline::loads_foreign_code(args));
    // `ipython --InteractiveShellApp.exec_lines=… x.py` runs code first.
    let code = code || read.runs_code;
    let file = read.script.is_some() || read.module.is_some();
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
    if code || stdin {
        return Launch::Reads(Reads::Interpreter);
    }
    // `python3 -m timeit CODE` runs the code it is given, `-m pdb` what it
    // reads; a module only known when it runs may be any.
    if let Some((module, _)) = &read.module {
        match module.known() {
            Some(name) if RUNS_GIVEN.contains(&name) => return Launch::Reads(Reads::Interpreter),
            Some(_) => {}
            None => return Launch::Unread(module.clone()),
        }
    }
    if let Some(script) = read.script.map(|at| &args[at]) {
        // `python3 "$F"`, `python3 <(curl …)`: a script only known when it
        // runs, or a download. What `xargs` hands on is the files a listing
        // names.
        if script.known().is_none() && *script != Arg::Input {
            return Launch::Unread(script.clone());
        }
        // `node --stack-size 100 <<'JS'`: an option node passes to V8 may
        // take the word, and node its code from the input.
        if read.unsure && input {
            return Launch::Reads(Reads::Interpreter);
        }
    }
    // Nothing to run reads the input (the REPL) where there is one to read,
    // and so does `-i` once the script has run.
    if (!file || read.interactive) && console {
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
pub(super) fn bun(unit: &Unit, input: bool) -> Launch {
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
    let launch = match with_code("bun", &args, bun_launch(unit, input)) {
        Launch::Inline(language, code) if run => Launch::Inline(
            language,
            inline::Code {
                plain: false,
                ..code
            },
        ),
        launch => launch,
    };
    only_runs(unit, evals || input, launch)
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
/// under a POSIX shell, and under cmd and PowerShell only when it is handed
/// one (`input`): something piped into it or a file redirected onto it.
fn repl(unit: &Unit, input: bool) -> Launch {
    if unit.shell == Shell::Posix || input {
        Launch::Reads(Reads::Interpreter)
    } else {
        Launch::Itself
    }
}

/// A line for cmd reads what `bun` and `deno` start (a package runner, a
/// delete tool, an npm specifier, `bun run name`, the shell script of `bun
/// exec`) as the other shells do. A script read from the input is read only
/// when the program is handed one, as for any interpreter in cmd: `reads` is
/// whether it is (something piped into it, a file redirected onto it), or
/// whether the line carries a flag that runs inline code: when the code
/// itself cannot be told (a module the options load, a subcommand in
/// between), the line still runs code the guard does not read, and stays
/// `unknown` in cmd as it is in the others. Inline code is not read in cmd.
fn only_runs(unit: &Unit, reads: bool, launch: Launch) -> Launch {
    match launch {
        Launch::Replace(_)
        | Launch::Inline(..)
        | Launch::Script(..)
        | Launch::Unread(_)
        | Launch::Encoded
        | Launch::Downloaded => launch,
        Launch::Either(first, second) => Launch::Either(
            Box::new(only_runs(unit, reads, *first)),
            Box::new(only_runs(unit, reads, *second)),
        ),
        // `bun --cwd DIR rimraf x`: what it starts in its folder is read the
        // same way.
        Launch::In(folder, shell, inner) => {
            Launch::In(folder, shell, Box::new(only_runs(unit, reads, *inner)))
        }
        _ if unit.shell != Shell::Cmd => launch,
        Launch::Reads(_) if reads => launch,
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
fn bun_launch(unit: &Unit, input: bool) -> Launch {
    let args = unit.args.as_slice();
    let first = after_options(args, &BUN_VALUES);
    let before = args.get(..first.unwrap_or(args.len())).unwrap_or_default();
    if before.iter().filter_map(Arg::known).any(bun_evals) {
        return Launch::Reads(Reads::Interpreter);
    }
    let by_value = first.map_or(Launch::Itself, |at| bun_subcommand(unit, at, input));
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
    let by_bun = bun_subcommand(unit, plain, input);
    match (by_value, by_bun) {
        (Launch::Itself, other) | (other, Launch::Itself) => other,
        // Two readings that come to the same are judged once.
        (value, bun) if value == bun => value,
        (value, bun) => Launch::Either(Box::new(value), Box::new(bun)),
    }
}

/// What the subcommand of `bun` at `first` does.
fn bun_subcommand(unit: &Unit, first: usize, input: bool) -> Launch {
    let args = unit.args.as_slice();
    // `bun "$F"`: a script, or a subcommand, only known when it runs.
    let Some(word) = args[first].known() else {
        return Launch::Unread(args[first].clone());
    };
    match word {
        "x" => runner("bun", unit),
        "repl" => repl(unit, input),
        // `bun exec 'script'` runs a shell script (bun's own shell, which
        // reads POSIX), its options standing before the script too.
        "exec" => {
            let rest = &args[first + 1..];
            after_options(rest, &BUN_VALUES).map_or(Launch::Itself, |at| {
                let script = Launch::Script(Shell::Posix, join(&rest[at..]));
                runner_in("bun", args, first + 1 + at, script)
            })
        }
        // `bun rimraf dir` runs the project's own delete tool by its name.
        name if DELETERS.contains(&name) => runner_in(
            "bun",
            args,
            first,
            Launch::Replace(Box::new(running(unit, "bun", first))),
        ),
        // `bun run name` runs a script of the project, a bin of it, or else
        // any program on the path (`bun run rm -rf x` deletes): a word that
        // is no file is judged as the program.
        "run" => match args
            .get(first + 1..)
            .and_then(|rest| after_options(rest, &BUN_VALUES))
            .map(|at| first + 1 + at)
        {
            // A code flag among the options of `run` (`bun -F x run -e
            // CODE`, also with the code joined to it: `-e'CODE'`,
            // `--eval=CODE`) is code given inline, read as `bun -e CODE` is.
            at if args[first + 1..at.unwrap_or(args.len())]
                .iter()
                .filter_map(Arg::known)
                .any(bun_evals) =>
            {
                Launch::Reads(Reads::Interpreter)
            }
            Some(at) if reads_input(&args[at]) => Launch::Reads(Reads::Interpreter),
            Some(at) if !is_file(&args[at]) => runner_in(
                "bun",
                args,
                at,
                Launch::Replace(Box::new(running(unit, "bun", at))),
            ),
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
pub(super) fn deno(unit: &Unit, input: bool) -> Launch {
    only_runs(
        unit,
        input,
        with_code("deno", &unit.args, deno_launch(unit, input)),
    )
}

fn deno_launch(unit: &Unit, input: bool) -> Launch {
    let args = unit.args.as_slice();
    let Some(first) = after_options(args, &DENO_VALUES) else {
        if let Some(launch) = deno_loads(args) {
            return launch;
        }
        let prints = args.iter().filter_map(Arg::known).any(|text| {
            matches!(text, "--version" | "-V" | "-v" | "--help" | "-h")
                || text.starts_with("--help=")
        });
        return if prints {
            Launch::Itself
        } else {
            repl(unit, input)
        };
    };
    // `deno --preload https://… main.ts`: what deno loads first runs.
    if let Some(launch) = deno_loads(&args[..first]) {
        return launch;
    }
    let Some(word) = args[first].known() else {
        return Launch::Reads(Reads::Interpreter);
    };
    let rest = &args[first + 1..];
    match word {
        "eval" => Launch::Reads(Reads::Interpreter),
        "repl" => deno_loads(rest).unwrap_or_else(|| repl(unit, input)),
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
        "run" | "watch" | "serve" => {
            let at = after_options_by(rest, |text, _| deno_word(text));
            if let Some(launch) = deno_loads(&rest[..at.unwrap_or(rest.len())]) {
                return launch;
            }
            at.map_or(Launch::Itself, |at| deno_target(unit, first + 1 + at))
        }
        // `deno test https://…`: every module it is given runs.
        "test" | "bench" => deno_loads(rest).unwrap_or_else(|| deno_modules(rest)),
        _ => deno_target(unit, first),
    }
}

/// The options of `deno serve`, `deno test` and `deno bench` that take the
/// next word, besides [`DENO_VALUES`].
const DENO_SUBCOMMAND_VALUES: [&str; 5] =
    ["--port", "--host", "--filter", "--reporter", "--junit-path"];

/// What a word that starts with a dash is among the options of deno's
/// subcommands that run modules.
fn deno_word(text: &str) -> Word {
    if DENO_VALUES.contains(&text) || DENO_SUBCOMMAND_VALUES.contains(&text) {
        Word::Value
    } else {
        Word::Flag
    }
}

/// Whether the module `spec` is code given in a `data:` URL, which deno runs
/// as it does a file: code on the line the guard does not read.
fn data_url(spec: &str) -> bool {
    spec.get(..5)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("data:"))
}

/// What the modules `deno test` and `deno bench` are given (the words that
/// are not options, before a `--`) do: one deno fetches is a download, one
/// in a `data:` URL is not read; files are their own business.
fn deno_modules(args: &[Arg]) -> Launch {
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        if text.starts_with('-') {
            if matches!(deno_word(text), Word::Value) {
                words.next();
            }
            continue;
        }
        if fetched(text) {
            return Launch::Downloaded;
        }
        if data_url(text) {
            return Launch::Encoded;
        }
    }
    Launch::Itself
}

/// What deno's options in `args` load before the script, when that is code
/// the line does not show: a module `--preload` (`--import`, `--require`)
/// or `--eval-file` names that deno fetches (`https:`, `jsr:`), or an import
/// map it fetches, which may point any import anywhere, is a download; a
/// `data:` URL is code the guard does not read; a module only known when it
/// runs is not read. Read up to a `--`.
fn deno_loads(args: &[Arg]) -> Option<Launch> {
    const LOADS: [&str; 5] = [
        "--preload",
        "--import",
        "--require",
        "--eval-file",
        "--import-map",
    ];
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let (name, value) = match text.split_once('=') {
            Some((name, value)) => (name, Some(Arg::Known(value.to_string()))),
            None => (text, None),
        };
        if !LOADS.contains(&name) {
            continue;
        }
        let Some(value) = value.or_else(|| words.next().cloned()) else {
            continue;
        };
        let map = name == "--import-map";
        let Some(value) = value.known() else {
            if map {
                continue;
            }
            return Some(Launch::Unread(value));
        };
        for spec in value.split(',') {
            if fetched(spec) {
                return Some(Launch::Downloaded);
            }
            if !map && data_url(spec) {
                return Some(Launch::Encoded);
            }
        }
    }
    None
}

/// The options of `deno task` that take the next word.
const DENO_TASK_VALUES: [&str; 5] = ["--cwd", "-c", "--config", "-f", "--filter"];

/// What `deno run` does with the script at `at`: its input is read as code,
/// an npm specifier is a package whose program runs, a script it fetches
/// from the network (`https:`, `http:`, a `jsr:` package) is a download, a
/// script only known when it runs is not read, a file is its own business.
fn deno_target(unit: &Unit, at: usize) -> Launch {
    let arg = &unit.args[at];
    match arg.known() {
        _ if reads_input(arg) => Launch::Reads(Reads::Interpreter),
        Some(spec) if spec.starts_with("npm:") => {
            Launch::Replace(Box::new(running_package(unit, "deno", at)))
        }
        Some(spec) if fetched(spec) => Launch::Downloaded,
        // `deno run 'data:application/javascript,…'`: code on the line,
        // not read.
        Some(spec) if data_url(spec) => Launch::Encoded,
        Some(_) => Launch::Itself,
        None => Launch::Unread(arg.clone()),
    }
}

/// Whether deno fetches the module `spec` from the network: a URL of
/// `http:` or `https:` (its scheme in any case, as a URL parser reads it)
/// or a package of the `jsr:` registry.
fn fetched(spec: &str) -> bool {
    let scheme = spec
        .split_once(':')
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    matches!(scheme.as_deref(), Some("http" | "https" | "jsr"))
}
