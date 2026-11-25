//! The real shells: where each is, which version it is, and how bash is
//! asked whether it accepts a line without running it.
//!
//! bash is started as `bash --noprofile --norc -r -n`, in a [`Room`], with
//! the line on its standard input and nothing else. `-n` is its no-exec
//! mode: it reads every command and runs none, and expands no word, so all
//! it can say is whether it accepts the line and, when it does not, its first
//! error (`tests/no_line_runs.rs` holds it to that: it opens no file a line
//! names, looks up no program or builtin, and answers the same whether a
//! named file exists or not). `--noprofile --norc` read no startup file, and
//! the room's environment has no `BASH_ENV`; `-r` (restricted) refuses what a
//! line could still do if one ran, and does not change how a line parses.
//!
//! zsh is not one of them: its no-exec mode (`zsh -n`) still expands words
//! (it opens the file of a `$(< FILE)`, takes `~` from the password database
//! whatever `HOME` it is given, looks up the program of `=cmd`), and its exit
//! status is not a parse verdict (`! cmd` ends with 1, a list left unfinished
//! at the end of the text is accepted). It is neither parse-only nor an
//! answer of accept or reject, so it is never started.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the tool looks for the shells on the PATH it was started with"
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::room::{Failure, Limits, Room, Start};

/// A real shell this tool compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// GNU bash, for the POSIX grammar.
    Bash,
    /// PowerShell 7 (`pwsh`), for the PowerShell grammar.
    Pwsh,
}

impl Kind {
    /// Every shell, in the order the report lists them.
    pub const ALL: [Self; 2] = [Self::Bash, Self::Pwsh];

    /// Its name, as the report and the known list write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Pwsh => "pwsh",
        }
    }

    /// The shell named `name` in the known list or on the command line.
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// Whether it reads POSIX lines (and not PowerShell's).
    pub const fn posix(self) -> bool {
        matches!(self, Self::Bash)
    }
}

/// The flags bash starts with that read no startup file: no profile (for a
/// login shell) and no `.bashrc` (for an interactive one). This tool starts
/// neither, and `BASH_ENV` never reaches bash (the room clears the
/// environment), so they matter only were `-n` to fail; the tests hold them
/// by the arguments the room is given.
pub const BASH_STARTUP: [&str; 2] = ["--noprofile", "--norc"];

/// The flags that keep a line from running: restricted mode, then no-exec
/// mode. `-n` is the one that holds: the tests run every canary again
/// without `-r`.
pub const BASH_NO_EXEC: [&str; 2] = ["-r", "-n"];

/// Every argument bash is started with to parse a line, in order.
pub fn bash_args() -> Vec<OsString> {
    BASH_STARTUP
        .iter()
        .chain(&BASH_NO_EXEC)
        .map(OsString::from)
        .collect()
}

/// The first `name` in the folders of `path_var` (a `PATH` value) that is a
/// file.
pub fn on_path(name: &str, path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path_var?)
        .map(|folder| folder.join(name))
        .find(|candidate| candidate.is_file() && candidate.is_absolute())
}

/// Ask bash at `path` its version, in `room`, with the same layers as a
/// parse; bash reads long options only before the others, and stops at
/// `--version`.
pub fn bash_version(path: &Path, room: &Room) -> Result<String, Failure> {
    let finished = room.start(&Start {
        program: path,
        args: BASH_STARTUP
            .iter()
            .chain(&["--version"])
            .map(OsString::from)
            .collect(),
        env: Vec::new(),
        stdin: b"",
        home_stays_empty: true,
        silent: false,
        limits: Limits::LINE,
    })?;
    version_in(Kind::Bash, &String::from_utf8_lossy(&finished.stdout))
        .ok_or_else(|| Failure::Start(format!("{} gave no version", path.display())))
}

/// The version in what a shell printed of itself.
pub fn version_in(kind: Kind, printed: &str) -> Option<String> {
    let first = printed.lines().next()?;
    let word = match kind {
        // `GNU bash, version 3.2.57(1)-release (arm64-apple-darwin26)`
        Kind::Bash => first.split("version ").nth(1)?,
        // `PowerShell 7.4.6`
        Kind::Pwsh => first.strip_prefix("PowerShell ")?,
    };
    let version: String = word
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!version.is_empty()).then_some(version)
}

/// What a shell said of a line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    /// It reads the line with no error.
    Accepts,
    /// It refuses the line, with its first error, as it wrote it but for
    /// its own name.
    Rejects(String),
}

/// How bash at `path` is started to parse `line`: in no-exec mode, the line
/// on its standard input, nothing on its standard output.
pub fn bash_parse<'a>(path: &'a Path, line: &'a str) -> Start<'a> {
    Start {
        program: path,
        args: bash_args(),
        env: Vec::new(),
        stdin: line.as_bytes(),
        home_stays_empty: true,
        silent: true,
        limits: Limits::LINE,
    }
}

/// Ask bash at `path` whether it accepts `line`, in no-exec mode, in `room`.
pub fn parse_bash(path: &Path, room: &Room, line: &str) -> Result<Verdict, Failure> {
    let finished = room.start(&bash_parse(path, line))?;
    let error = first_error(&String::from_utf8_lossy(&finished.stderr));
    match finished.code {
        // A warning (a here-document that ends at the end of the text) is
        // still a line bash accepts and runs.
        Some(0) => Ok(Verdict::Accepts),
        // bash ends a refused line with 2, and says why.
        Some(2) => {
            Ok(Verdict::Rejects(error.unwrap_or_else(|| {
                "refuses the line, and says nothing".to_string()
            })))
        }
        other => Err(Failure::Start(format!(
            "{} ended with {other:?} on a line: {}",
            path.display(),
            error.unwrap_or_default()
        ))),
    }
}

/// The first error line bash printed, without its own name in front
/// (`/bin/bash: line 1: …`), so the same error reads the same from every path
/// to it.
pub fn first_error(stderr: &str) -> Option<String> {
    let line = stderr.lines().find(|line| !line.trim().is_empty())?;
    let message = line.split_once(": ").map_or(line, |(_, rest)| rest);
    Some(message.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_is_read_from_what_each_shell_prints() {
        let bash = "GNU bash, version 3.2.57(1)-release (arm64-apple-darwin26)\nCopyright";
        assert_eq!(version_in(Kind::Bash, bash).as_deref(), Some("3.2.57"));
        let bash5 = "GNU bash, version 5.2.21(1)-release (x86_64-pc-linux-gnu)";
        assert_eq!(version_in(Kind::Bash, bash5).as_deref(), Some("5.2.21"));
        assert_eq!(
            version_in(Kind::Pwsh, "PowerShell 7.4.6").as_deref(),
            Some("7.4.6")
        );
        assert_eq!(version_in(Kind::Pwsh, "something else"), None);
        assert_eq!(version_in(Kind::Bash, ""), None);
    }

    #[test]
    fn an_error_loses_the_name_of_the_shell() {
        assert_eq!(
            first_error(
                "/bin/bash: line 2: syntax error near unexpected token `)'\n/bin/bash: line 2: `)'\n"
            )
            .as_deref(),
            Some("line 2: syntax error near unexpected token `)'")
        );
        assert_eq!(first_error("\n  \n"), None);
    }

    #[test]
    fn every_shell_is_named_once() {
        for kind in Kind::ALL {
            assert_eq!(Kind::named(kind.name()), Some(kind));
        }
        assert_eq!(Kind::named("zsh"), None);
        assert_eq!(Kind::named("cmd"), None);
        assert!(Kind::Bash.posix() && !Kind::Pwsh.posix());
    }
}
