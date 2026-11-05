//! Judges one read or write of a path through a file API: [`judge`].
//!
//! A shell line shows what a shell is about to do; an agent also reads and
//! writes files through a file API, and no line shows those calls. This guard
//! takes the two things such a call has, an [`Access`] and the path as the
//! agent wrote it, and says whether it is safe to do without asking, or risky
//! and why.
//!
//! The path is one literal path. It is resolved by its spelling alone, by
//! core's path model, against the [`Paths`] the caller passes: relative to
//! the working directory, `~` as the home directory, `..` applied, and the
//! Windows spellings (drives, shares, long paths, short names, any case)
//! read as Windows reads them, whatever host the guard runs on. Nothing is
//! read from the disk, so a symlink is judged by its own name.
//!
//! - A **read** is safe wherever it lands, except a key or a credential
//!   ([`Rule::ReadSecret`]). An agent reads widely, and reading is what a
//!   caller lets run unasked.
//! - A **write** (an edit, a create, an append, a rename's target) is safe
//!   inside a workspace folder, to a temporary file and to the null device.
//!   Anywhere else it is a finding: beyond the workspace
//!   ([`Rule::WriteOutside`]), to a key, a startup file, a file a tool runs
//!   on its own (`.envrc`, `.vscode/tasks.json`, `.github/workflows/*`) or the
//!   repository's history ([`Rule::WriteSensitive`]), or to what the caller
//!   gates with
//!   ([`Rule::WriteProtected`]).
//! - A path that is not one literal path, or that cannot be placed, is
//!   [`Rule::Unreadable`]; one on another machine is
//!   [`Rule::NetworkShare`].
//!
//! The guard only judges. What to do about each rule is the caller's policy.
//!
//! ```
//! use milo_guards_file::{judge, Access, Paths, Rule};
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
//!
//! assert!(judge(Access::Read, "src/main.rs", &paths).is_safe());
//! assert!(judge(Access::Write, "src/main.rs", &paths).is_safe());
//!
//! let assessment = judge(Access::Read, "~/.ssh/id_ed25519", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::ReadSecret);
//! assert_eq!(assessment.findings()[0].reason, "reads your SSH keys");
//!
//! let assessment = judge(Access::Write, "../other/x", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::WriteOutside);
//! ```

use milo_guards_core::spelling::{glob, network, verbatim};
use milo_guards_core::{Flavour, Place, Resolver, Sensitivity, Spelling};

pub use milo_guards_core::{Paths, Protected, ProtectedKind};

/// What a file API call does to the path.
///
/// Exhaustive on purpose: a verb added later must break each caller's
/// `match`. An edit, a create, an append and a rename's target are all
/// [`Write`](Access::Write); the guard has no finer verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    /// Reads the file.
    Read,
    /// Changes the file, creates it, or puts something at that name.
    Write,
}

/// What [`judge`] concluded about a read or a write: safe, or risky with
/// every finding.
pub type Assessment = milo_guards_core::Assessment<Rule>;

/// One reason a read or a write is risky: the rule that found it, what it
/// would do in a few words a permission prompt can show (`reads your SSH
/// keys`), and the path as written.
pub type Finding = milo_guards_core::Finding<Rule>;

/// The rules a path is judged by. Each finding names one.
///
/// This enum is exhaustive on purpose: a rule added here breaks every
/// caller's `match` at compile time, so each caller decides what to do with
/// the new rule. [`Rule::ALL`] lists every rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Reads a key or a credential: a place core knows holds one, or a path
    /// under it. Not the repository's history, not a shell startup file and
    /// not a protected path: reading those is safe.
    ReadSecret,
    /// Writes beyond the workspace: outside it, a system folder, the home
    /// directory, the workspace folder itself, a disk.
    WriteOutside,
    /// Writes to a key, a credential, a shell startup file, a file a tool
    /// runs on its own (`.envrc`, `.vscode/tasks.json`, a CI workflow) or the
    /// repository's history.
    WriteSensitive,
    /// Writes to a path the caller named in `Paths::protected`, with the
    /// caller's words in the reason, so a caller can refuse this one and
    /// only ask on the others.
    WriteProtected,
    /// Reaches a network share (`\\server\share`): Windows offers the user's
    /// login to the server. Read or write, and in addition to the rule the
    /// place itself breaks.
    NetworkShare,
    /// Is not one literal path, or cannot be placed: empty, too long, a
    /// control character, a wildcard, a variable, another user's `~`, or a
    /// name only known when it runs.
    Unreadable,
}

impl Rule {
    /// Every rule, in the order the design page lists them.
    pub const ALL: [Self; 6] = [
        Self::ReadSecret,
        Self::WriteOutside,
        Self::WriteSensitive,
        Self::WriteProtected,
        Self::NetworkShare,
        Self::Unreadable,
    ];

    /// The rule's stable name on the wire (`read_secret`). It never changes
    /// once a caller uses it, whatever the variant is called in code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadSecret => "read_secret",
            Self::WriteOutside => "write_outside",
            Self::WriteSensitive => "write_sensitive",
            Self::WriteProtected => "write_protected",
            Self::NetworkShare => "network_share",
            Self::Unreadable => "unreadable",
        }
    }
}

impl milo_guards_core::RuleName for Rule {
    fn name(self) -> &'static str {
        Rule::name(self)
    }
}

/// The longest path judged, in bytes: what the longest systems' own path
/// limit allows (`PATH_MAX`). A longer one is [`Rule::Unreadable`].
pub const MAX_PATH_LEN: usize = 4096;

/// Judge `access` to `path`, a file API's one literal path, against the
/// directories in `paths`.
///
/// ```
/// use milo_guards_file::{judge, Access, Paths, Rule};
///
/// let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
/// // A file API takes one path, so a wildcard or a variable is not one.
/// let assessment = judge(Access::Read, "$HOME/.ssh/id_rsa", &paths);
/// assert_eq!(assessment.findings()[0].rule, Rule::Unreadable);
/// ```
#[must_use = "the assessment is the answer: it says whether the access is safe"]
pub fn judge(access: Access, path: &str, paths: &Paths) -> Assessment {
    let resolver = Resolver::new(paths);
    let flavour = resolver.flavour();
    let share = network(path, flavour);
    let mut findings = Vec::new();
    let target = (path.len() <= MAX_PATH_LEN).then(|| path.to_string());
    let mut add = |rule: Rule, reason: String| {
        if !findings.iter().any(|found: &Finding| found.rule == rule) {
            findings.push(Finding {
                rule,
                reason,
                target: target.clone(),
                instead: None,
            });
        }
    };

    let readings = match readings(path, flavour) {
        Ok(readings) => readings,
        Err(problem) => {
            add(Rule::Unreadable, problem.to_string());
            if share {
                add(Rule::NetworkShare, SHARE.to_string());
            }
            return risky(findings);
        }
    };
    // A bracket class (`app/[id]/page.tsx`) is read as the resolver reads a
    // pattern; where that is not the agent's own place it names more than
    // one file, which is not one literal path.
    let class = glob::has_wildcard(body(path, flavour));
    let mut inside = false;
    for (at, reading) in readings.iter().enumerate() {
        let place = resolver.place_hidden(*reading, flavour, true);
        // The plain spelling is the last reading.
        inside |= at + 1 == readings.len() && is_the_callers(place);
        if class && !place.harmless() {
            add(
                Rule::Unreadable,
                "has a pattern that can name more than one file".to_string(),
            );
            continue;
        }
        // A git folder at any depth, a hook named for what it does.
        if let Some(words) = resolver
            .git(*reading, flavour)
            .filter(|_| access == Access::Write)
        {
            add(Rule::WriteSensitive, format!("writes to {words}"));
        }
        // A file a tool runs on its own, in a workspace folder at any depth
        // (`.vscode/tasks.json`, `.envrc`, `.github/workflows/ci.yml`): to
        // write one is to plant code. Reading one is everyday work.
        if let Some(words) = resolver
            .startup(*reading, flavour, true)
            .filter(|_| access == Access::Write)
        {
            add(Rule::WriteSensitive, format!("writes to {words}"));
        }
        if let Some((rule, reason)) = of_place(access, place) {
            add(rule, reason);
        }
        // What the kernel serves is a file only by name: to read it is to
        // read what it holds, and to write it is to write whatever it is
        // (`/dev/fd/3` is any file the process has open).
        if let Some(words) = resolver.kernel(*reading, flavour) {
            match access {
                Access::Read => add(Rule::ReadSecret, format!("reads {words}")),
                Access::Write => add(Rule::WriteOutside, format!("writes to {words}")),
            }
        }
    }
    if share && !inside {
        add(Rule::NetworkShare, SHARE.to_string());
    }
    risky(findings)
}

/// Whether a place is one the caller itself works in or gates with: a share
/// holding the workspace is the caller's own, and reaching it is no news.
fn is_the_callers(place: Place) -> bool {
    matches!(
        place,
        Place::Inside
            | Place::Workspace { .. }
            | Place::Protected(_)
            | Place::Sensitive(_, Sensitivity::History)
    )
}

/// The reason a network share gives.
const SHARE: &str = "reaches a network share";

fn risky(findings: Vec<Finding>) -> Assessment {
    if findings.is_empty() {
        Assessment::Safe
    } else {
        Assessment::Risky(findings)
    }
}

/// The rule a place breaks for `access`, and the reason, if it breaks one.
fn of_place(access: Access, place: Place) -> Option<(Rule, String)> {
    // What is not known when it runs can be anywhere.
    if place == Place::Unknown {
        return Some((Rule::Unreadable, format!("is {}", place.words())));
    }
    match access {
        Access::Read => match place {
            Place::Sensitive(words, Sensitivity::Secret) => {
                Some((Rule::ReadSecret, format!("reads {words}")))
            }
            // Raw bytes of a disk hold every key on it, however it is named.
            Place::Disk => Some((
                Rule::ReadSecret,
                "reads a disk, and every key on it".to_string(),
            )),
            Place::Sensitive(_, Sensitivity::Startup | Sensitivity::History) => None,
            // An agent reads widely: anything else is its own business.
            _ => None,
        },
        Access::Write => match place {
            place if place.harmless() => None,
            Place::Sensitive(words, _) => {
                Some((Rule::WriteSensitive, format!("writes to {words}")))
            }
            Place::Protected(words) => Some((Rule::WriteProtected, format!("writes to {words}"))),
            place => Some((Rule::WriteOutside, format!("writes to {}", place.words()))),
        },
    }
}

/// The spellings the path can mean, the one the agent most likely meant
/// first: a `~` at the start is the home directory (agents write it meaning
/// home), and also a folder named `~` in the working directory, since a file
/// API may not expand it. `Err` says why the path is not one literal path.
fn readings(path: &str, flavour: Flavour) -> Result<Vec<Spelling<'_>>, &'static str> {
    if path.is_empty() {
        return Err("is empty");
    }
    if path.len() > MAX_PATH_LEN {
        return Err("is too long to read");
    }
    if path.chars().any(char::is_control) {
        return Err("has a control character");
    }
    if path.starts_with(char::is_whitespace) {
        return Err("starts with a space");
    }
    if body(path, flavour).contains(['*', '?']) {
        return Err("has a wildcard");
    }
    if has_variable(path) {
        return Err("has a variable or a command");
    }
    let Some(rest) = path.strip_prefix('~') else {
        return Ok(vec![Spelling::Plain(path)]);
    };
    if rest.is_empty() || rest.starts_with(flavour.separators()) {
        return Ok(vec![Spelling::Home(rest), Spelling::Plain(path)]);
    }
    // `~user`: a home directory the spelling does not name.
    Err("is another user's home directory")
}

/// The path without a long path's prefix: its `?` is part of the prefix,
/// not a wildcard.
fn body(path: &str, flavour: Flavour) -> &str {
    match flavour {
        Flavour::Windows => verbatim(path).unwrap_or(path),
        Flavour::Posix => path,
    }
}

/// Whether `path` holds a variable or a command a shell or an API would
/// replace: `$` and a name (`$HOME`, `${X}`, `$(cmd)`, `$env:X`), `%name%`,
/// or a backtick (`` `cmd` ``, PowerShell's escape). A `$` is a plain
/// character only at the end of the path, or before a separator, a space or
/// a dot; a `%` only when no `%` closes a name after it.
fn has_variable(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.bytes().enumerate().any(|(at, byte)| match byte {
        b'`' => true,
        b'$' => !matches!(bytes.get(at + 1), None | Some(b'/' | b'\\' | b' ' | b'.')),
        b'%' => path[at + 1..]
            .split_once('%')
            .is_some_and(|(name, _)| !name.is_empty() && !name.contains(['/', '\\'])),
        _ => false,
    })
}

/// The README's example, compiled and run with the doctests so it cannot
/// drift from the code. Only rustdoc's doctest pass reads the file, so
/// building this crate never needs the README.
#[cfg(doctest)]
#[allow(
    clippy::disallowed_macros,
    reason = "the README include is read by rustdoc's doctest pass only"
)]
#[doc = include_str!("../README.md")]
mod readme {}
