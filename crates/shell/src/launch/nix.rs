//! Nix's runners: `nix run`, which runs a package's program, `nix shell`
//! and `nix develop`, which run the command after `-c` (`--command`), and
//! `nix-shell`, which runs the shell line `--run` or `--command` gives.
//!
//! Nix takes any of its settings as an option (`--max-jobs 4`, `--sandbox`,
//! `--no-sandbox`), so an option the guard does not know may take the word
//! after it: where the command starts is then not known, and the line is
//! not read.

use super::tools::{unknown_before, UNKNOWN_OPTION};
use super::wrappers::running;
use super::{runs, Launch};
use crate::unit::{Arg, Unit};
use crate::Shell;

/// The options of `nix` that take one value.
const NIX_VALUES: &[&str] = &[
    "-f",
    "--file",
    "--expr",
    "-I",
    "--include",
    "-j",
    "--max-jobs",
    "--cores",
    "--store",
    "--eval-store",
    "--log-format",
    "--builders",
    "--substituters",
    "--experimental-features",
    "--inputs-from",
    "--reference-lock-file",
    "--output-lock-file",
    "--update-input",
    "--profile",
    "--priority",
    "-k",
    "--keep",
    "--keep-env-var",
    "-u",
    "--unset",
    "--unset-env-var",
    "--arg-from-stdin",
    "-o",
    "--out-link",
    "--phase",
    "--max-silent-time",
    "--timeout",
    "--system",
    "--eval-system",
    "--log-lines",
];

/// The options of `nix` that take two values.
const NIX_PAIRS: &[&str] = &[
    "--option",
    "--arg",
    "--argstr",
    "--arg-from-file",
    "--override-input",
    "--override-flake",
    "--redirect",
    "--set-env-var",
];

/// The options of `nix` that take no value.
const NIX_FLAGS: &[&str] = &[
    "--debug",
    "--help",
    "--version",
    "--offline",
    "--refresh",
    "--repair",
    "--impure",
    "--quiet",
    "--verbose",
    "--print-build-logs",
    "--commit-lock-file",
    "--recreate-lock-file",
    "--dry-run",
    "--json",
    "--print-out-paths",
    "--rebuild",
    "--stdin",
    "--derivation",
    "--show-trace",
    "--keep-going",
    "--keep-failed",
    "--fallback",
    "--accept-flake-config",
    "--pure-eval",
    "--sandbox",
    "--ignore-environment",
    "--ignore-env",
    "--build",
    "--check",
    "--configure",
    "--install",
    "--installcheck",
    "--unpack",
];

/// The short options of `nix` that take a value, and those that take none.
const NIX_SHORT_VALUES: &str = "fIjkuo";
const NIX_SHORT_FLAGS: &str = "LviK";

/// The subcommands of `nix` that run a command.
const NIX_RUNS: &[&str] = &["run", "shell", "develop"];

/// The options of `nix-shell` that take one value.
const NIX_SHELL_VALUES: &[&str] = &[
    "-A",
    "--attr",
    "-I",
    "--include",
    "-i",
    "--exclude",
    "--keep",
    "-j",
    "--max-jobs",
    "--cores",
    "--max-silent-time",
    "--timeout",
    "-o",
    "--out-link",
    "--add-root",
    "--store",
    "--log-format",
    "--builders",
    "--substituters",
    "--experimental-features",
    "--system",
];

/// The options of `nix-shell` that take two values.
const NIX_SHELL_PAIRS: &[&str] = &["--arg", "--argstr", "--option"];

/// The options of `nix-shell` that take no value.
const NIX_SHELL_FLAGS: &[&str] = &[
    "-p",
    "--packages",
    "-E",
    "--expr",
    "--pure",
    "--impure",
    "--no-out-link",
    "--dry-run",
    "-Q",
    "--no-build-output",
    "-K",
    "--keep-failed",
    "-k",
    "--keep-going",
    "--fallback",
    "--readonly-mode",
    "--show-trace",
    "-v",
    "--verbose",
    "--quiet",
    "--repair",
    "--check",
    "--help",
    "--version",
    "--debug",
];

/// The short options of `nix-shell` that take a value, and those that take
/// none.
const NIX_SHELL_SHORT_VALUES: &str = "AIijo";
const NIX_SHELL_SHORT_FLAGS: &str = "pEQKkv";

/// The options of one of Nix's programs, read as it reads them.
struct Options {
    values: &'static [&'static str],
    pairs: &'static [&'static str],
    flags: &'static [&'static str],
    short_values: &'static str,
    short_flags: &'static str,
}

const NIX: Options = Options {
    values: NIX_VALUES,
    pairs: NIX_PAIRS,
    flags: NIX_FLAGS,
    short_values: NIX_SHORT_VALUES,
    short_flags: NIX_SHORT_FLAGS,
};

const NIX_SHELL: Options = Options {
    values: NIX_SHELL_VALUES,
    pairs: NIX_SHELL_PAIRS,
    flags: NIX_SHELL_FLAGS,
    short_values: NIX_SHELL_SHORT_VALUES,
    short_flags: NIX_SHELL_SHORT_FLAGS,
};

/// How many words the option `text` takes, itself among them, as Nix reads
/// it; `None` for one the guard does not know. A setting turned off
/// (`--no-NAME`) takes none and one added to (`--extra-NAME`) takes one, as
/// any setting does. Short letters may be bundled (`-vvL`), and Nix splits a
/// bundle into its letters up to the first that is not one: a letter that
/// takes a value takes what follows it in the bundle (`-j4`), or the next
/// word at the end of it.
fn option(text: &str, options: &Options) -> Option<usize> {
    if text.starts_with("--") {
        return if options.pairs.contains(&text) {
            Some(3)
        } else if options.values.contains(&text) || text.starts_with("--extra-") {
            Some(2)
        } else if options.flags.contains(&text) || text.starts_with("--no-") {
            Some(1)
        } else {
            None
        };
    }
    if options.values.contains(&text) {
        return Some(2);
    }
    if options.flags.contains(&text) {
        return Some(1);
    }
    let bundle = text.strip_prefix('-')?;
    for (at, letter) in bundle.char_indices() {
        if options.short_values.contains(letter) {
            return Some(if at + letter.len_utf8() == bundle.len() {
                2
            } else {
                1
            });
        }
        if !options.short_flags.contains(letter) {
            return None;
        }
    }
    Some(1)
}

/// Whether `text` is an option word: a dash and something after it.
fn is_option(text: &str) -> bool {
    text.len() > 1 && text.starts_with('-')
}

/// `nix run INSTALLABLE [-- ARGS]` runs the package's program with the
/// arguments: the program is named by the attribute after `#`
/// (`nixpkgs#hello` runs `hello`), and a flake's own app (`nix run .`, or
/// `nix run -- ARGS` with none named) is the user's. The package sets which
/// of its programs runs, which need not be its name, and may be one that
/// runs its arguments; so the words after `--` are also read as a command,
/// and the riskier reading counts.
///
/// `nix shell INSTALLABLES… -c CMD…` and `nix develop [INSTALLABLE] -c
/// CMD…` (`--command`) run the command, every word after `-c`, with the
/// packages on its path; without `-c` they start a shell.
pub(super) fn nix(unit: &Unit) -> Launch {
    let args = &unit.args;
    let mut at = 0;
    let mut sub = None;
    // The options stand before and after the subcommand; the installable of
    // `run` is the first other word after it.
    let installable = loop {
        let Some(arg) = args.get(at) else {
            return Launch::Itself;
        };
        match (sub, arg.known()) {
            (Some("shell" | "develop"), Some("-c" | "--command")) => {
                return runs(args, Some(at + 1));
            }
            // `nix run -- ARGS` runs the flake of the folder it is in, its
            // default app, with the words after `--`.
            (Some("run"), Some("--")) => return runs(args, Some(at + 1)),
            (None, Some("--")) => return Launch::Itself,
            // The words after it are installables to Nix; a `-c` among them
            // is still read as one.
            (Some(_), Some("--")) => at += 1,
            (_, Some(text)) if is_option(text) => match option(text, &NIX) {
                Some(taken) => at += taken,
                None if sub.is_some() => return Launch::Opaque(UNKNOWN_OPTION),
                None => return unknown_before(args, at + 1, NIX_RUNS),
            },
            (None, word) => {
                match word {
                    Some(word) if NIX_RUNS.contains(&word) => sub = Some(word),
                    _ => return Launch::Itself,
                }
                at += 1;
            }
            (Some("run"), _) => break at,
            // An installable of `nix shell` or `nix develop`.
            (Some(_), _) => at += 1,
        }
    };
    let dash = args.get(installable + 1).and_then(Arg::known) == Some("--");
    let rest = installable + 1 + usize::from(dash);
    let package = match args[installable].known().and_then(attribute) {
        Some(name) => {
            let mut run = running(unit, "nix", installable);
            run.program = Arg::Known(name.to_string());
            run.args = args[rest.min(args.len())..].to_vec();
            Launch::Replace(Box::new(run))
        }
        None => Launch::Itself,
    };
    match runs(args, Some(rest)) {
        command @ Launch::Runs(_) if dash => Launch::Either(Box::new(package), Box::new(command)),
        _ => package,
    }
}

/// The program an installable names: the last part of its attribute path
/// (`nixpkgs#python3Packages.black` is `black`), without the outputs
/// (`^bin`). `None` without one.
fn attribute(installable: &str) -> Option<&str> {
    let (_, path) = installable.split_once('#')?;
    let path = path.split('^').next().unwrap_or(path);
    let name = path.rsplit('.').next().unwrap_or(path);
    (!name.is_empty()).then_some(name)
}

/// `nix-shell [OPTIONS] [PATH | -p PACKAGES…]` runs the shell line `--run`
/// or `--command` gives in bash, the last one when there are several, as
/// Nix keeps the last; without one it starts a shell. Its other words are
/// files, expressions or packages, and the options stand among them.
pub(super) fn nix_shell(args: &[Arg]) -> Launch {
    let mut script = None;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--run" | "--command") => {
                script = args.get(at + 1).cloned();
                at += 2;
            }
            Some(text) if is_option(text) => match option(text, &NIX_SHELL) {
                Some(taken) => at += taken,
                None => return Launch::Opaque(UNKNOWN_OPTION),
            },
            _ => at += 1,
        }
    }
    script.map_or(Launch::Itself, |script| {
        Launch::Script(Shell::Posix, script)
    })
}
