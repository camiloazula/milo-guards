//! The tools that run their arguments as a command: tracers and runners
//! (`strace`, `script`, `ssh-agent`, `chronic`), `launchctl asuser`,
//! `bsexec` and `submit`, `wsl`, `lima`, `nix run`, and the runners that load
//! secrets into the command's environment first (`aws-vault exec`, `doppler
//! run`, `op run`, `infisical run`, `direnv exec`, `dotenv`).

use super::wrappers::running;
use super::{
    after_getopt, after_options, getopt_value, join, runs, shell_words, subcommand, Launch,
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
    let playback = args[..file].iter().filter_map(Arg::known).any(|text| {
        text.strip_prefix('-')
            .is_some_and(|bundle| !bundle.starts_with('-') && bundle.contains('p'))
    });
    if playback {
        return Launch::Itself;
    }
    let mut start = file + 1;
    if args.get(start).and_then(Arg::known) == Some("--") {
        start += 1;
    }
    runs(args, Some(start))
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
pub(super) fn wsl(args: &[Arg]) -> Launch {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("--") => return linux_line(&args[at + 1..]),
            Some("-e" | "--exec") => {
                return match &args[at + 1..] {
                    [] => Launch::Itself,
                    words => Launch::Script(Shell::Posix, shell_words(words)),
                };
            }
            Some(text) if WSL_VALUES.contains(&text) => at += 2,
            // `wsl ~` starts in the home directory, as `--cd ~` does.
            Some("--system" | "~") => at += 1,
            Some(text) if text.starts_with('-') => return Launch::Itself,
            _ => return linux_line(&args[at..]),
        }
    }
    Launch::Itself
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

/// `lima` runs its words in the default Lima virtual machine.
pub(super) fn lima(args: &[Arg]) -> Launch {
    runs(args, Some(0))
}

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
    "--extra-substituters",
    "--experimental-features",
    "--extra-experimental-features",
    "--inputs-from",
    "--reference-lock-file",
    "--output-lock-file",
    "--update-input",
    "--profile",
    "--priority",
    "-k",
    "--keep",
    "-u",
    "--unset",
    "--arg-from-stdin",
];

/// The options of `nix` that take two values.
const NIX_PAIRS: &[&str] = &[
    "--option",
    "--arg",
    "--argstr",
    "--arg-from-file",
    "--override-input",
    "--override-flake",
];

/// `nix run INSTALLABLE [-- ARGS]` runs the package's program with the
/// arguments: the program is named by the attribute after `#`
/// (`nixpkgs#hello` runs `hello`), and a flake's own app (`nix run .`, or
/// `nix run -- ARGS` with none named) is the user's. The package sets which of its programs runs, which need not
/// be its name, and may be one that runs its arguments; so the words after
/// `--` are also read as a command, and the riskier reading counts.
pub(super) fn nix(unit: &Unit) -> Launch {
    let args = &unit.args;
    let mut at = 0;
    let mut sub = None;
    // The options stand before and after `run`; the installable is the first
    // other word after it.
    let installable = loop {
        let Some(arg) = args.get(at) else {
            return Launch::Itself;
        };
        match arg.known() {
            Some(text) if NIX_PAIRS.contains(&text) => at += 3,
            Some(text) if NIX_VALUES.contains(&text) => at += 2,
            // `nix run -- ARGS` runs the flake of the folder it is in, its
            // default app, with the words after `--`.
            Some("--") if sub.is_some() => return runs(args, Some(at + 1)),
            Some("--") => return Launch::Itself,
            Some(text) if text.starts_with('-') => at += 1,
            _ if sub.is_none() => {
                if arg.known() != Some("run") {
                    return Launch::Itself;
                }
                sub = Some(at);
                at += 1;
            }
            _ => break at,
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

/// The options of `doppler` and `doppler run` that take a value.
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
];

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
/// options (or after `--`) with secrets in its environment. `doppler run
/// --command` and `infisical run --command` run a shell line instead: in the
/// system shell, `cmd` on Windows.
pub(super) fn secrets_run(key: &str, unit: &Unit) -> Launch {
    let args = &unit.args;
    let (short, long, command) = match key {
        "doppler" => (DOPPLER_SHORT, DOPPLER_LONG, true),
        "infisical" => (INFISICAL_SHORT, INFISICAL_LONG, true),
        _ => ("", OP_LONG, false),
    };
    let Some(from) = subcommand(args, "run", short, long) else {
        return Launch::Itself;
    };
    let own = &args[from..];
    if command {
        if let Some(line) = getopt_value(own, None, "command", short, long) {
            let shell = if unit.shell == Shell::Posix {
                Shell::Posix
            } else {
                Shell::Cmd
            };
            return Launch::Script(shell, line);
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
