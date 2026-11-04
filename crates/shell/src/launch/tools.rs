//! The tools that run their arguments as a command: tracers and runners
//! (`strace`, `ltrace`, `script`, `ssh-agent`, `chronic`), `launchctl
//! asuser`, `bsexec` and `submit`, `wsl`, `lima` and `limactl shell`,
//! `nsenter`, and the runners that load secrets into the command's
//! environment first (`aws-vault exec`, `doppler run`, `op run`, `infisical
//! run`, `direnv exec`, `dotenv`). And the files the tracers, `script` and
//! `time` write their own output to.

use std::collections::HashSet;

use super::wrappers::{folder_option, getopt, running, Getopt};
use super::{
    after_assignments, after_getopt, after_options, after_options_by, getopt_value, getopt_word,
    join, runs, shell_word, shell_words, subcommand, Launch, Word,
};
use crate::unit::{Arg, Unit};
use crate::Shell;

/// The options of `strace` that take a value: its short letters, and the long
/// options whose value may follow as the next word.
const STRACE_SHORT: &str = "abeEIoOpPsSuUX";
const STRACE_LONG: &[&str] = &[
    "output",
    "trace",
    "trace-path",
    "signal",
    "status",
    "abbrev",
    "verbose",
    "raw",
    "read",
    "write",
    "fault",
    "inject",
    "kvm",
    "decode-pids",
    "string-limit",
    "columns",
    "attach",
    "user",
    "env",
    "summary-sort-by",
    "summary-columns",
    "argv0",
    "const-print-style",
    "detach-on",
];

/// `strace` runs the program after its options, tracing it.
pub(super) fn strace(args: &[Arg]) -> Launch {
    runs(args, after_getopt(args, STRACE_SHORT, STRACE_LONG))
}

/// The short options of `nsenter` that take a value, the rest of the bundle
/// or the next word: the target process (`-t`), the socket (`-N`) and the
/// user and group ids (`-S`, `-G`).
const NSENTER_VALUED: &str = "tNSG";

/// The short options of `nsenter` whose value, a namespace's file or a
/// folder, is only ever the rest of the bundle (`-m/proc/1/ns/mnt`,
/// `-W/srv`): with nothing after them they take the target's.
const NSENTER_ATTACHED: &str = "muinpCUTrwW";

/// The long options of `nsenter` that take the next word as their value.
const NSENTER_LONG: &[&str] = &["target", "net-socket", "setuid", "setgid"];

/// The long options of `nsenter` that take no value, or one only after `=`.
const NSENTER_FLAGS: &[&str] = &[
    "all",
    "mount",
    "uts",
    "ipc",
    "net",
    "pid",
    "cgroup",
    "user",
    "time",
    "user-parent",
    "root",
    "wd",
    "wdns",
    "env",
    "no-fork",
    "preserve-credentials",
    "keep-caps",
    "join-cgroup",
    "follow-context",
    "help",
    "version",
];

/// The short options of `nsenter` that start the program in another working
/// folder: `-w` and `-W` move it to one, `-r` to the target's root, and
/// entering a mount namespace (`-m`, or `-a`, every namespace) moves it to
/// that namespace's root, as the kernel does on `setns`.
const NSENTER_MOVES: &str = "wWrma";

/// The long options of [`NSENTER_MOVES`].
const NSENTER_MOVES_LONG: &[&str] = &["wd", "wdns", "root", "mount", "all"];

/// Whether `name`, a long option of `nsenter` as written without its
/// `=value`, is one of `options`: by its full name, or, as `getopt_long`
/// reads one, by a prefix of it that is no option's full name.
fn nsenter_long(name: &str, options: &[&str]) -> bool {
    let exact = |option: &&str| *option == name;
    if NSENTER_LONG.iter().chain(NSENTER_FLAGS).any(exact) {
        return options.iter().any(exact);
    }
    !name.is_empty() && options.iter().any(|option| option.starts_with(name))
}

/// What an option of `nsenter` is, as its `getopt_long` reads it.
fn nsenter_word(text: &str) -> Word {
    if let Some(name) = text.strip_prefix("--") {
        return if !name.contains('=') && nsenter_long(name, NSENTER_LONG) {
            Word::Value
        } else {
            Word::Flag
        };
    }
    let bundle = text.strip_prefix('-').unwrap_or(text);
    for (at, letter) in bundle.char_indices() {
        if NSENTER_ATTACHED.contains(letter) {
            return Word::Flag;
        }
        if NSENTER_VALUED.contains(letter) {
            return if at + letter.len_utf8() == bundle.len() {
                Word::Value
            } else {
                Word::Flag
            };
        }
    }
    Word::Flag
}

/// Whether an option of `nsenter` starts the program in another working
/// folder ([`NSENTER_MOVES`]).
fn nsenter_moves(text: &str) -> bool {
    if let Some(name) = text.strip_prefix("--") {
        let name = name.split('=').next().unwrap_or(name);
        return nsenter_long(name, NSENTER_MOVES_LONG);
    }
    let bundle = text.strip_prefix('-').unwrap_or(text);
    for letter in bundle.chars() {
        if NSENTER_MOVES.contains(letter) {
            return true;
        }
        if NSENTER_ATTACHED.contains(letter) || NSENTER_VALUED.contains(letter) {
            return false;
        }
    }
    false
}

/// `nsenter` runs the program after its options in the namespaces of
/// another process, the init process's among them (`nsenter -t 1 -a`).
/// The options of [`NSENTER_MOVES`] start it in a folder of that process's,
/// or in one they are given inside its namespace, which the line does not
/// show: where it runs is then only known when it does.
pub(super) fn nsenter(args: &[Arg]) -> Launch {
    let start = after_options_by(args, |text, _| nsenter_word(text));
    let launch = runs(args, start);
    let own = start
        .and_then(|start| args.get(..start))
        .unwrap_or_default();
    let moved = own
        .iter()
        .filter_map(Arg::known)
        .take_while(|text| *text != "--")
        .find(|text| text.starts_with('-') && nsenter_moves(text));
    match (moved, &launch) {
        (Some(option), Launch::Runs(_)) => {
            Launch::In(Arg::Unknown(option.to_string()), None, Box::new(launch))
        }
        _ => launch,
    }
}

/// The options of `script` that take a value: util-linux's and the BSDs'
/// (`-t time` on the BSDs and macOS). FreeBSD's `-F pipe` takes one too, and
/// macOS's `-F` none: [`script`] reads it both ways.
const SCRIPT_SHORT: &str = "cEIOBTmot";
const SCRIPT_LONG: &[&str] = &[
    "command",
    "echo",
    "log-in",
    "log-out",
    "log-io",
    "log-timing",
    "logging-format",
    "output-limit",
];

/// `script`: `-c` (`--command`) runs a shell line, wherever it stands, as
/// util-linux reads its options; otherwise the words after the file it
/// records to are the command (the BSDs and macOS). `-p` plays a recording
/// back and runs nothing. `-F` takes a value on FreeBSD and none on macOS,
/// so where the two readings differ both are judged.
pub(super) fn script(args: &[Arg]) -> Launch {
    let flag = script_with(args, SCRIPT_SHORT);
    let valued = script_with(args, &format!("{SCRIPT_SHORT}F"));
    if flag == valued {
        flag
    } else {
        Launch::Either(Box::new(valued), Box::new(flag))
    }
}

/// [`script`] with the options of `short` taking a value.
fn script_with(args: &[Arg], short: &str) -> Launch {
    if let Some(line) = getopt_value(args, Some('c'), "command", short, SCRIPT_LONG) {
        return Launch::Script(Shell::Posix, line);
    }
    let Some(file) = after_getopt(args, short, SCRIPT_LONG) else {
        return Launch::Itself;
    };
    if plays_back(&args[..file], short) {
        return Launch::Itself;
    }
    let mut start = file + 1;
    if args.get(start).and_then(Arg::known) == Some("--") {
        start += 1;
    }
    runs(args, Some(start))
}

/// Whether `script`'s options `options`, read with the letters of `short`
/// taking a value, play a recording back: `-p` as a flag letter in a
/// bundle, before the first letter that takes a value (`-dp`, not `-cpwd`
/// or `-Bperf.log`), and never the value of an option (`-c -p`).
fn plays_back(options: &[Arg], short: &str) -> bool {
    let mut at = 0;
    while let Some(text) = options.get(at).and_then(Arg::known) {
        let Some(bundle) = text.strip_prefix('-').filter(|_| text != "--") else {
            break;
        };
        if !bundle.starts_with('-')
            && bundle
                .chars()
                .take_while(|letter| !short.contains(*letter))
                .any(|letter| letter == 'p')
        {
            return true;
        }
        at += match getopt_word(text, short, SCRIPT_LONG) {
            Word::Value => 2,
            Word::Flag | Word::Operand => 1,
        };
    }
    false
}

/// The options of `ltrace` that take a value, as `getopt_long` reads them.
const LTRACE_OPTIONS: Getopt = Getopt {
    short: &[
        ('a', "align"),
        ('A', "array"),
        ('D', "debug"),
        ('e', "expr"),
        ('F', "config"),
        ('l', "library"),
        ('n', "indent"),
        ('o', "output"),
        ('p', "pid"),
        ('s', "string"),
        ('u', "user"),
        ('w', "where"),
        ('x', "symbols"),
    ],
    long: &[
        ("align", true),
        ("config", true),
        ("debug", true),
        ("demangle", false),
        ("help", false),
        ("indent", true),
        ("library", true),
        ("no-signals", false),
        ("output", true),
        ("version", false),
        ("where", true),
    ],
};

/// `ltrace` runs the program after its options, tracing its library calls.
pub(super) fn ltrace(args: &[Arg]) -> Launch {
    runs(
        args,
        after_options_by(args, |text, next| getopt(text, next, &LTRACE_OPTIONS).0),
    )
}

/// The options of GNU `time` (`-a`, `-p`, `-q` and `-v` take none), which
/// also names a long one by a shorter start of it; the BSDs' and macOS's
/// `-o` is the same.
pub(super) const TIME_OPTIONS: Getopt = Getopt {
    short: &[('f', "format"), ('o', "output")],
    long: &[
        ("append", false),
        ("format", true),
        ("help", false),
        ("output", true),
        ("portability", false),
        ("quiet", false),
        ("verbose", false),
        ("version", false),
    ],
};

/// The options of `script` read for the files it writes: util-linux's and
/// the BSDs', with the long names util-linux gives them (a long one may be
/// shortened, as `getopt_long` reads it). `-t` takes its file attached on
/// util-linux and a time on the BSDs: its value is read as a file either
/// way. [`SCRIPT_PIPE`] adds FreeBSD's `-F pipe`.
const SCRIPT_OPTIONS: Getopt = Getopt {
    short: &[
        ('c', "command"),
        ('E', "echo"),
        ('I', "log-in"),
        ('O', "log-out"),
        ('B', "log-io"),
        ('T', "log-timing"),
        ('m', "logging-format"),
        ('o', "output-limit"),
        ('t', "timing"),
    ],
    long: SCRIPT_LONGS,
};

/// [`SCRIPT_OPTIONS`] with FreeBSD's `-F pipe`, the named pipe it also
/// writes the session to.
const SCRIPT_PIPE: Getopt = Getopt {
    short: &[
        ('c', "command"),
        ('E', "echo"),
        ('I', "log-in"),
        ('O', "log-out"),
        ('B', "log-io"),
        ('T', "log-timing"),
        ('m', "logging-format"),
        ('o', "output-limit"),
        ('t', "timing"),
        ('F', "pipe"),
    ],
    long: SCRIPT_LONGS,
};

/// util-linux `script`'s long options. `--timing` takes its file only after
/// `=`, which [`script_option`] reads.
const SCRIPT_LONGS: &[(&str, bool)] = &[
    ("append", false),
    ("command", true),
    ("echo", true),
    ("flush", false),
    ("force", false),
    ("help", false),
    ("log-in", true),
    ("log-io", true),
    ("log-out", true),
    ("log-timing", true),
    ("logging-format", true),
    ("output-limit", true),
    ("quiet", false),
    ("return", false),
    ("timing", false),
    ("version", false),
];

/// The options of `script` whose value is a file it writes.
const SCRIPT_WRITES: [&str; 6] = [
    "log-in",
    "log-out",
    "log-io",
    "log-timing",
    "timing",
    "pipe",
];

/// What a tracer, a recorder or a timer writes its own output to, beside
/// the command it runs.
pub(super) enum Output {
    /// A file, written as a redirect writes it.
    File(Arg),
    /// A command a shell runs, given the output on its input: `strace -o
    /// '|cmd'` (or `'!cmd'`).
    Command(Arg),
}

/// What the program `key` writes its own output to, by `args`: `strace -o`
/// (`--output`), `ltrace -o` (`--output`), `time -o` (`--output`, with or
/// without `-a`), and `script`'s file (`typescript` when it names none) and
/// the files of its `-B`, `-I`, `-O`, `-T` and `-t` (see [`script_outputs`]).
pub(super) fn outputs(key: &str, args: &[Arg]) -> Vec<Output> {
    match key {
        "strace" => written(args, false, strace_option)
            .into_iter()
            .map(strace_output)
            .collect(),
        "ltrace" => written(args, false, |text, next| {
            named(getopt(text, next, &LTRACE_OPTIONS), &["output"])
        })
        .into_iter()
        .map(Output::File)
        .collect(),
        "time" => written(args, false, |text, next| {
            named(getopt(text, next, &TIME_OPTIONS), &["output"])
        })
        .into_iter()
        .map(Output::File)
        .collect(),
        "script" => script_outputs(args).into_iter().map(Output::File).collect(),
        _ => Vec::new(),
    }
}

/// The values of the options among a program's own, before what it runs,
/// that `read` says are files it writes: `read` is given each word that
/// starts with a dash and the word after it, and says what the word is (see
/// [`Word`]) and the file it names. When the program `permutes` its
/// arguments, as GNU `getopt` does, its options are read among its operands
/// too, up to a `--`.
fn written(
    args: &[Arg],
    permutes: bool,
    read: impl Fn(&str, Option<&Arg>) -> (Word, Option<Arg>),
) -> Vec<Arg> {
    let mut files = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => break,
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                let (word, file) = read(text, args.get(at + 1));
                files.extend(file);
                at += match word {
                    Word::Flag => 1,
                    Word::Value => 2,
                    Word::Operand if permutes => 1,
                    Word::Operand => break,
                };
            }
            _ if permutes => at += 1,
            _ => break,
        }
    }
    files
}

/// What [`getopt`] read, with the value of an option among `writes`.
fn named(read: (Word, Option<(&str, Option<Arg>)>), writes: &[&str]) -> (Word, Option<Arg>) {
    let (word, option) = read;
    let file = option
        .filter(|(name, _)| writes.contains(name))
        .and_then(|(_, value)| value);
    (word, file)
}

/// `strace`'s option `text`, read as [`strace`] reads it, and the file of
/// `-o` (in a bundle or attached) or `--output` (or `--output=`).
fn strace_option(text: &str, next: Option<&Arg>) -> (Word, Option<Arg>) {
    let word = getopt_word(text, STRACE_SHORT, STRACE_LONG);
    let file = if let Some(long) = text.strip_prefix("--") {
        match long.split_once('=') {
            Some(("output", value)) => Some(Arg::Known(value.to_string())),
            None if long == "output" => next.cloned(),
            _ => None,
        }
    } else {
        let bundle = text.strip_prefix('-').unwrap_or(text);
        bundle
            .char_indices()
            .find(|(_, letter)| STRACE_SHORT.contains(*letter))
            .filter(|(_, letter)| *letter == 'o')
            .and_then(|(at, letter)| match &bundle[at + letter.len_utf8()..] {
                "" => next.cloned(),
                rest => Some(Arg::Known(rest.to_string())),
            })
    };
    (word, file)
}

/// The output `file` of `strace -o`: a name that starts with `|` or `!` is
/// a command strace pipes its output to, run by a shell.
fn strace_output(file: Arg) -> Output {
    match &file {
        Arg::Known(text) => match text.strip_prefix(['|', '!']) {
            Some(command) => Output::Command(Arg::Known(command.to_string())),
            None => Output::File(file),
        },
        Arg::Template { text, .. } if text.starts_with(['|', '!']) => Output::Command(file),
        _ => Output::File(file),
    }
}

/// The files `script` writes: the one it records to, the first word after
/// its options (`typescript`, in the folder it runs in, when there is none),
/// unless `-p` plays that back (see [`plays_back`]), and the files of `-B`, `-I`, `-O` and `-T`
/// (`--log-io`, `--log-in`, `--log-out`, `--log-timing`), of `-t` and
/// `--timing=`, and of FreeBSD's `-F pipe`, wherever they stand, as
/// util-linux reads its options. Both readings of `-F` (see [`script`]) are
/// taken.
fn script_outputs(args: &[Arg]) -> Vec<Arg> {
    let mut files: Vec<Arg> = Vec::new();
    let mut seen: HashSet<Arg> = HashSet::new();
    for (short, spec) in [
        (SCRIPT_SHORT.to_string(), &SCRIPT_OPTIONS),
        (format!("{SCRIPT_SHORT}F"), &SCRIPT_PIPE),
    ] {
        let file = after_getopt(args, &short, SCRIPT_LONG);
        let recorded = match file {
            _ if plays_back(&args[..file.unwrap_or(args.len())], &short) => None,
            Some(at) => args.get(at).cloned(),
            None => Some(Arg::Known("typescript".to_string())),
        };
        let options = written(args, true, |text, next| script_option(text, next, spec));
        for file in recorded.into_iter().chain(options) {
            if seen.insert(file.clone()) {
                files.push(file);
            }
        }
    }
    files
}

/// `script`'s option `text` read by `spec`, and the file it names:
/// `--timing=FILE` (or a shorter start of it) names one too.
fn script_option(text: &str, next: Option<&Arg>, spec: &Getopt) -> (Word, Option<Arg>) {
    if let Some((name, value)) = text
        .strip_prefix("--")
        .and_then(|long| long.split_once('='))
    {
        if !name.is_empty() && "timing".starts_with(name) {
            return (Word::Flag, Some(Arg::Known(value.to_string())));
        }
    }
    named(getopt(text, next, spec), &SCRIPT_WRITES)
}

/// `ssh-agent` runs the program after its options with the agent's socket in
/// its environment.
pub(super) fn ssh_agent(args: &[Arg]) -> Launch {
    runs(args, after_getopt(args, "aEOPt", &[]))
}

/// `chronic` (moreutils) runs the program after its flags, and shows its
/// output only when it fails.
pub(super) fn chronic(args: &[Arg]) -> Launch {
    runs(args, after_options(args, &[]))
}

/// `launchctl asuser UID cmd…` and `launchctl bsexec PID cmd…` run a program;
/// `launchctl submit … -- cmd…` starts one as a job, `-p` naming the program
/// whose arguments (its own name first) follow the `--`.
pub(super) fn launchctl(unit: &Unit) -> Launch {
    let args = &unit.args;
    match args.first().and_then(Arg::known) {
        Some("asuser" | "bsexec") => runs(args, Some(2)),
        Some("submit") => {
            let Some(dash) = args.iter().position(|arg| arg.known() == Some("--")) else {
                return Launch::Itself;
            };
            let own = &args[1..dash];
            let program = own
                .iter()
                .position(|arg| arg.known() == Some("-p"))
                .and_then(|at| own.get(at + 1));
            match program {
                Some(program) if dash + 1 < args.len() => {
                    let mut run = running(unit, "launchctl", dash + 1);
                    run.program = program.clone();
                    Launch::Replace(Box::new(run))
                }
                _ => runs(args, Some(dash + 1)),
            }
        }
        _ => Launch::Itself,
    }
}

/// The options of `wsl` that take a value.
const WSL_VALUES: [&str; 7] = [
    "-d",
    "--distribution",
    "--distribution-id",
    "-u",
    "--user",
    "--cd",
    "--shell-type",
];

/// `wsl` runs its words as a line in the Linux shell of a distribution:
/// after its options (a `~` among them is one, to start in the home
/// directory), or all of them after `--`. `-e` (`--exec`) runs the
/// words after it as a program and its arguments, with no shell. Any other
/// option (`--list`, `--install`, `--shutdown`) manages WSL and runs no
/// command; with no words it opens a shell.
///
/// Windows hands `wsl` one command line, which it passes on to the shell as
/// it is. How the line it is started from turns its arguments into that
/// line, an argument with a space quoted or not, is not on the line, so both
/// are read and the riskier counts: `wsl pwsh -c "Remove-Item …"` runs
/// `Remove-Item …` as one script, `wsl 'rm -rf ~'` may run `rm -rf ~`.
///
/// `--cd DIR` starts the shell in `DIR` (see [`in_linux`]): `wsl --cd
/// C:\Windows rm -rf System32` deletes `/mnt/c/Windows/System32`, which is
/// `C:\Windows\System32`.
pub(super) fn wsl(args: &[Arg]) -> Launch {
    let mut folder = None;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => return in_linux(folder.as_ref(), linux_line(&args[at + 1..])),
            Some("-e" | "--exec") => {
                return match &args[at + 1..] {
                    [] => Launch::Itself,
                    words => in_linux(
                        folder.as_ref(),
                        Launch::Script(Shell::Posix, shell_words(words)),
                    ),
                };
            }
            Some("--cd") => {
                folder = args.get(at + 1).cloned();
                at += 2;
            }
            Some(text) if WSL_VALUES.contains(&text) => at += 2,
            // `wsl ~` starts in the home directory, as `--cd ~` does.
            Some("--system" | "~") => at += 1,
            Some(text) if text.starts_with('-') => return Launch::Itself,
            _ => return in_linux(folder.as_ref(), linux_line(&args[at..])),
        }
    }
    Launch::Itself
}

/// `launch`, started by `wsl --cd` in `folder` when there is one: a Linux
/// path, `~` the Linux home, and an absolute Windows path the folder WSL
/// mounts it at (`C:\Windows` is `/mnt/c/Windows`). WSL refuses any other
/// path; it is read as a Linux path all the same.
fn in_linux(folder: Option<&Arg>, launch: Launch) -> Launch {
    let Some(folder) = folder else {
        return launch;
    };
    let folder = match folder.known() {
        Some(text) => Arg::Known(linux_path(text)),
        None => folder.clone(),
    };
    Launch::In(folder, Some(Shell::Posix), Box::new(launch))
}

/// The Linux path WSL reads a `--cd` folder as: an absolute Windows path
/// (`C:\Windows`, `C:/Windows`, `C:`) under `/mnt/` and its drive letter,
/// with its backslashes as slashes.
fn linux_path(text: &str) -> String {
    let mut chars = text.chars();
    if let (Some(letter), Some(':')) = (chars.next(), chars.next()) {
        let rest = chars.as_str();
        if letter.is_ascii_alphabetic() && (rest.is_empty() || rest.starts_with(['\\', '/'])) {
            return format!(
                "/mnt/{}{}",
                letter.to_ascii_lowercase(),
                rest.replace('\\', "/")
            );
        }
    }
    text.to_string()
}

/// The line `wsl` hands its Linux shell, read the two ways [`wsl`] says.
fn linux_line(words: &[Arg]) -> Launch {
    if words.is_empty() {
        return Launch::Itself;
    }
    let plain = join(words);
    let quoted = windows_line(words);
    if quoted == plain {
        Launch::Script(Shell::Posix, plain)
    } else {
        Launch::Either(
            Box::new(Launch::Script(Shell::Posix, quoted)),
            Box::new(Launch::Script(Shell::Posix, plain)),
        )
    }
}

/// Arguments made into a Windows command line: one with a space, or empty,
/// in double quotes, and a double quote in one after a backslash.
fn windows_line(words: &[Arg]) -> Arg {
    let line = words
        .iter()
        .map(|arg| {
            let text = arg.text().replace('"', "\\\"");
            if text.is_empty() || text.contains(char::is_whitespace) {
                format!("\"{text}\"")
            } else {
                text
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if words.iter().all(|arg| arg.known().is_some()) {
        Arg::Known(line)
    } else {
        Arg::Unknown(line)
    }
}

/// Why a wrapper's command is not read when the wrapper is given an option
/// the guard does not know: the option may take the word after it, so where
/// the command starts, or what it is, is not known.
pub(super) const UNKNOWN_OPTION: &str = "runs a command after an option that cannot be read";

/// The index of the first word of `args`, from `at`, that is not one of a
/// wrapper's options, `read` giving how many words each option takes, itself
/// among them; a `--` ends the options. `Err` with the index of an option
/// `read` does not know (`None`).
pub(super) fn after_known(
    args: &[Arg],
    mut at: usize,
    read: impl Fn(&str) -> Option<usize>,
) -> Result<usize, usize> {
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => return Ok(at + 1),
            Some(text) if text.len() > 1 && text.starts_with('-') => match read(text) {
                Some(taken) => at += taken,
                None => return Err(at),
            },
            _ => return Ok(at),
        }
    }
    Ok(at)
}

/// Why a wrapper's command is not read when a word only known when it runs
/// stands where its options or its subcommand do: the word may be the
/// option, or the subcommand, that runs a command.
pub(super) const UNKNOWN_WORD: &str = "runs a command after a word only known when it runs";

/// Whether one of `words` is among `args` from `at`.
pub(super) fn follows(args: &[Arg], at: usize, words: &[&str]) -> bool {
    args.get(at..)
        .unwrap_or_default()
        .iter()
        .any(|arg| arg.known().is_some_and(|text| words.contains(&text)))
}

/// What a program does when it is given an option the guard does not know
/// before its subcommand, which the option may take as its value: when one
/// of the `subcommands` that run a command follows, from `at`, that command
/// is not read; otherwise the program is judged itself.
pub(super) fn unknown_before(args: &[Arg], at: usize, subcommands: &[&str]) -> Launch {
    if follows(args, at, subcommands) {
        Launch::Opaque(UNKNOWN_OPTION)
    } else {
        Launch::Itself
    }
}

/// What a program does when a word only known when it runs stands where its
/// subcommand does: when one of `words`, which follow the subcommand that
/// runs a command, follows from `at`, the word may be that subcommand, and
/// the command is not read; otherwise the program is judged itself.
pub(super) fn unknown_subcommand(args: &[Arg], at: usize, words: &[&str]) -> Launch {
    if follows(args, at, words) {
        Launch::Opaque(UNKNOWN_WORD)
    } else {
        Launch::Itself
    }
}

/// How many words the option `text` takes, itself among them, as a Go
/// program built on cobra reads it: `--name=value` and `-xVALUE` one, a
/// long option of `long_values` or a short one of `short_values` two at the
/// end of its word, one of `long_flags` or `short_flags` one (short flags in
/// a bundle). `None` for one the guard does not know.
pub(super) fn cobra_option(
    text: &str,
    short_values: &str,
    short_flags: &str,
    long_values: &[&str],
    long_flags: &[&str],
) -> Option<usize> {
    if let Some(long) = text.strip_prefix("--") {
        let (name, value) = long
            .split_once('=')
            .map_or((long, None), |(name, value)| (name, Some(value)));
        let valued = long_values.contains(&name);
        return if !valued && !long_flags.contains(&name) {
            None
        } else if valued && value.is_none() {
            Some(2)
        } else {
            Some(1)
        };
    }
    let bundle = text.strip_prefix('-')?;
    for (at, letter) in bundle.char_indices() {
        if short_values.contains(letter) {
            return Some(if at + letter.len_utf8() == bundle.len() {
                2
            } else {
                1
            });
        }
        if !short_flags.contains(letter) {
            return None;
        }
    }
    Some(1)
}

/// `lima` runs its words in the default Lima virtual machine: it is a
/// script that hands them all to `limactl shell --instance default`, so
/// `limactl shell`'s options may stand first, a `--` ends them, and the
/// words after them are the command.
pub(super) fn lima(args: &[Arg]) -> Launch {
    let Ok(start) = after_known(args, 0, limactl_option) else {
        return Launch::Opaque(UNKNOWN_OPTION);
    };
    guest_command(args, &args[..start], start)
}

/// The long options of `limactl` and `limactl shell` that take a value.
const LIMACTL_VALUES: &[&str] = &["log-level", "log-format", "shell", "workdir"];

/// The long options of `limactl` and `limactl shell` that take none.
const LIMACTL_FLAGS: &[&str] = &[
    "debug",
    "tty",
    "help",
    "version",
    "reconnect",
    "preserve-env",
    "start",
];

/// How many words an option of `limactl` takes (see [`cobra_option`]).
fn limactl_option(text: &str) -> Option<usize> {
    cobra_option(text, "", "hv", LIMACTL_VALUES, LIMACTL_FLAGS)
}

/// `limactl shell [OPTIONS] INSTANCE [--] [CMD…]` runs the command in the
/// Lima virtual machine `INSTANCE`; without one it starts the shell. The
/// options end at the instance, and one `--` right after it is taken off:
/// the words after them are the command's.
pub(super) fn limactl(args: &[Arg]) -> Launch {
    let sub = match after_known(args, 0, limactl_option) {
        Ok(sub) => sub,
        Err(at) => return unknown_before(args, at + 1, &["shell"]),
    };
    match args.get(sub) {
        Some(arg) if arg.known() == Some("shell") => {}
        Some(arg) if arg.known().is_none() => return unknown_subcommand(args, sub + 1, &["shell"]),
        _ => return Launch::Itself,
    }
    let Ok(instance) = after_known(args, sub + 1, limactl_option) else {
        return Launch::Opaque(UNKNOWN_OPTION);
    };
    let mut start = instance + 1;
    if args.get(start).and_then(Arg::known) == Some("--") {
        start += 1;
    }
    guest_command(args, args.get(sub + 1..instance).unwrap_or_default(), start)
}

/// The command `limactl shell` runs from `start`, with its options `own`.
/// Lima quotes each word and hands the line to the machine's shell, but
/// leaves the leading words with a `=` as assignments, their names
/// unquoted: a `NAME=value` sets a variable for the command, and a word
/// whose name is not one is shell text, so the line is read as the shell
/// reads it. `--workdir DIR` starts the command in `DIR`, a path of the
/// machine; without it Lima runs `cd` to the folder the line is in, and to
/// the home directory when that folder is not shared with the machine, so
/// the command is read from both.
fn guest_command(args: &[Arg], own: &[Arg], start: usize) -> Launch {
    let program = after_assignments(args, start);
    let launch = match args.get(program).and_then(Arg::known) {
        Some(text) if text.contains('=') => {
            Launch::Script(Shell::Posix, guest_line(&args[start..]))
        }
        _ => runs(args, Some(program)),
    };
    if !matches!(launch, Launch::Runs(_) | Launch::Script(..)) {
        return launch;
    }
    let folder = folder_option(own, &["--workdir"], false, |text, _| {
        if limactl_option(text) == Some(2) {
            Word::Value
        } else {
            Word::Flag
        }
    });
    match folder {
        Some(folder) => Launch::In(folder, Some(Shell::Posix), Box::new(launch)),
        None => Launch::Either(
            Box::new(launch.clone()),
            Box::new(Launch::In(
                Arg::Known("~".to_string()),
                Some(Shell::Posix),
                Box::new(launch),
            )),
        ),
    }
}

/// The line Lima builds from the words of a command: each leading word with
/// a `=` its name as it is and its value quoted, every other word quoted.
fn guest_line(words: &[Arg]) -> Arg {
    let mut assigning = true;
    let line = words
        .iter()
        .map(|arg| {
            let text = arg.text();
            match text.split_once('=') {
                Some((name, value)) if assigning => format!("{name}={}", shell_word(value)),
                _ => {
                    assigning = false;
                    shell_word(text)
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if words.iter().all(|arg| arg.known().is_some()) {
        Arg::Known(line)
    } else {
        Arg::Unknown(line)
    }
}

/// The options of `aws-vault` and its `exec` that take a value.
const AWS_VAULT_SHORT: &str = "dt";
const AWS_VAULT_LONG: &[&str] = &[
    "duration",
    "mfa-token",
    "region",
    "backend",
    "prompt",
    "keychain",
    "secret-service-collection",
    "pass-dir",
    "pass-cmd",
    "pass-prefix",
    "file-dir",
];

/// `aws-vault exec PROFILE [--] cmd…` runs the command with the profile's
/// credentials; with no command it starts a shell.
pub(super) fn aws_vault(args: &[Arg]) -> Launch {
    let Some(from) = subcommand(args, "exec", AWS_VAULT_SHORT, AWS_VAULT_LONG) else {
        return Launch::Itself;
    };
    let Some(profile) =
        after_getopt(&args[from..], AWS_VAULT_SHORT, AWS_VAULT_LONG).map(|at| from + at)
    else {
        return Launch::Itself;
    };
    let mut start = profile + 1;
    if args.get(start).and_then(Arg::known) == Some("--") {
        start += 1;
    }
    runs(args, Some(start))
}

/// The options of `doppler` and `doppler run` that take a value: short,
/// then long.
const DOPPLER_SHORT: &str = "pc";
const DOPPLER_LONG: &[&str] = &[
    "project",
    "config",
    "token",
    "api-host",
    "dashboard-host",
    "configuration",
    "scope",
    "fallback",
    "passphrase",
    "name-transformer",
    "mount",
    "mount-format",
    "mount-template",
    "mount-max-reads",
    "only-secrets",
    "command",
    "timeout",
    "attempts",
    "dns-resolver-address",
    "dns-resolver-proto",
];

/// The options of `doppler` and `doppler run` that take none.
const DOPPLER_FLAGS: &[&str] = &[
    "debug",
    "json",
    "silent",
    "print-config",
    "no-check-version",
    "no-verify-tls",
    "no-timeout",
    "no-read-env",
    "fallback-readonly",
    "fallback-only",
    "no-fallback",
    "no-cache",
    "forward-signals",
    "preserve-env",
    "watch",
    "no-exit-on-write-failure",
    "enable-dns-resolver",
    "help",
    "version",
];

/// How many words an option of `doppler` takes (see [`cobra_option`]).
fn doppler_option(text: &str) -> Option<usize> {
    cobra_option(text, DOPPLER_SHORT, "h", DOPPLER_LONG, DOPPLER_FLAGS)
}

/// The options of `infisical` and `infisical run` that take a value.
const INFISICAL_SHORT: &str = "t";
const INFISICAL_LONG: &[&str] = &[
    "env",
    "path",
    "projectId",
    "token",
    "domain",
    "tags",
    "command",
    "log-level",
    "watch-interval",
];

/// The options of `op` and `op run` that take a value.
const OP_LONG: &[&str] = &[
    "account",
    "config",
    "encoding",
    "format",
    "session",
    "env-file",
    "environment",
];

/// `doppler run`, `infisical run` and `op run` run the command after their
/// options (or after `--`) with secrets in its environment, from any shell.
/// `doppler run --command` and `infisical run --command` run a shell line
/// instead: in the system shell, `cmd` on Windows. `doppler`'s options are
/// all known to the guard, and one it does not know leaves its command
/// unread.
pub(super) fn secrets_run(key: &str, unit: &Unit) -> Launch {
    let args = &unit.args;
    let system = if unit.shell == Shell::Posix {
        Shell::Posix
    } else {
        Shell::Cmd
    };
    if key == "doppler" {
        let sub = match after_known(args, 0, doppler_option) {
            Ok(sub) => sub,
            Err(at) => return unknown_before(args, at + 1, &["run"]),
        };
        match args.get(sub) {
            Some(arg) if arg.known() == Some("run") => {}
            Some(arg) if arg.known().is_none() => {
                return unknown_subcommand(args, sub + 1, &["run", "--"])
            }
            _ => return Launch::Itself,
        }
        let Ok(start) = after_known(args, sub + 1, doppler_option) else {
            return Launch::Opaque(UNKNOWN_OPTION);
        };
        let own = &args[sub + 1..];
        if let Some(line) = getopt_value(own, None, "command", DOPPLER_SHORT, DOPPLER_LONG) {
            return Launch::Script(system, line);
        }
        return runs(args, Some(start));
    }
    let (short, long, command) = match key {
        "infisical" => (INFISICAL_SHORT, INFISICAL_LONG, true),
        _ => ("", OP_LONG, false),
    };
    let Some(from) = subcommand(args, "run", short, long) else {
        return Launch::Itself;
    };
    let own = &args[from..];
    if command {
        if let Some(line) = getopt_value(own, None, "command", short, long) {
            return Launch::Script(system, line);
        }
    }
    runs(args, after_getopt(own, short, long).map(|at| from + at))
}

/// `direnv exec DIR cmd…` runs the command with the environment `DIR`'s
/// `.envrc` sets.
pub(super) fn direnv(args: &[Arg]) -> Launch {
    match args.first().and_then(Arg::known) {
        Some("exec") => runs(args, Some(2)),
        _ => Launch::Itself,
    }
}

/// `dotenv` (dotenv-cli) runs the command after its options (`-e FILE`,
/// `-v NAME=value`, `-p NAME`, `-c ENV`), or after `--`, with the variables
/// of its files.
pub(super) fn dotenv(args: &[Arg]) -> Launch {
    runs(args, after_getopt(args, "evpc", &[]))
}
