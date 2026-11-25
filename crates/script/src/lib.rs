//! Judges Python or JavaScript code an agent runs directly: [`judge`].
//!
//! An agent runs code through a shell line (`python3 -c …`, `node -e …`),
//! which the shell guard judges, but also through a tool that runs code with
//! no shell around it: a Python tool, a notebook, a JavaScript sandbox. This
//! guard takes such code as it is, with its [`Language`] and the [`Paths`]
//! the agent works in, and says whether it is safe to run without asking, or
//! risky and why.
//!
//! The code is read by the code reader (`milo-guards-code`), which says what
//! it is certain to do: the files it deletes, writes, reads and moves, the
//! programs it starts, the code it runs. Each act is judged here against
//! core's path model, as the shell guard judges the same act in the code a
//! line hands an interpreter, with the same rule names and the same reasons:
//!
//! - a delete or a move of anything beyond the workspace, the workspace
//!   itself, a key, a startup file, the repository's history or a protected
//!   path is [`Rule::Delete`]; a write there is [`Rule::Overwrite`]; a change
//!   of permissions or owner there is [`Rule::Permissions`]; a write over a
//!   disk is [`Rule::WipeDisk`];
//! - a read of a key or a credential, or of a file the caller named as one
//!   with [`Paths::with_secrets`], is [`Rule::ReadSecret`], in the caller's
//!   words;
//! - code that starts a program or a shell command is [`Rule::RunProgram`]:
//!   this guard does not judge the program, which is the shell guard's, and
//!   the finding's `target` is the command as a line of the machine's shell
//!   ([`target_shell`] says which), for the caller to ask the shell guard
//!   about; on Windows a target is only ever words that cmd and the C
//!   runtime both read as themselves, and elsewhere the program has none. Code that starts a program
//!   is never read whole, so it is always [`Rule::Unknown`] too: the target
//!   says which program, and what the shell guard finds in it adds to the
//!   answer, but a safe answer for every target never makes the code safe;
//! - code that runs code it downloads is [`Rule::RunDownloaded`];
//! - code the reader does not follow, or does not understand whole, is
//!   [`Rule::Unknown`] when nothing worse is found in it, never safe; code
//!   too long, too deep or that does not parse is [`Rule::Unreadable`].
//!
//! Code read whole that does none of it is safe: `print(1)`,
//! `console.log(1)`, `open('out.txt', 'w')` inside the workspace. Python
//! looks for a module in the folder it runs in first, even with no `import`
//! (an uncaught exception imports `traceback`), so Python is safe only when
//! the working directory is the workspace's own.
//!
//! The guard only judges. What to do about each rule is the caller's policy.
//!
//! ```
//! use milo_guards_script::{judge, Language, Paths, Rule};
//!
//! let paths = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
//!
//! assert!(judge(Language::Python, "print(1)", &paths).is_safe());
//!
//! let code = "import shutil; shutil.rmtree('/home/me')";
//! let assessment = judge(Language::Python, code, &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::Delete);
//! assert_eq!(assessment.findings()[0].reason, "deletes your home directory");
//!
//! // A program is the shell guard's to judge: the target is its command line.
//! // The code is not read whole, so it is `unknown` as well, whatever the
//! // program is.
//! let code = "require('child_process').execFileSync('git', ['push', '--force'])";
//! let assessment = judge(Language::JavaScript, code, &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::RunProgram);
//! assert_eq!(assessment.findings()[0].target.as_deref(), Some("git push --force"));
//! assert_eq!(assessment.findings()[1].rule, Rule::Unknown);
//!
//! // Code the reader does not understand whole is never safe.
//! let assessment = judge(Language::Python, "import json; print(json.dumps(1))", &paths);
//! assert_eq!(assessment.findings()[0].rule, Rule::Unknown);
//! ```

mod judge;
#[cfg(feature = "testing")]
#[doc(hidden)]
pub mod testing;

pub use milo_guards_code::Language;
pub use milo_guards_core::{Link, Links, Paths, Protected, ProtectedKind, Secret};

/// What [`judge`] concluded about a piece of code: safe, or risky with every
/// finding.
pub type Assessment = milo_guards_core::Assessment<Rule>;

/// One reason code is risky: the rule that found it, what it would do in a
/// few words a permission prompt can show (`deletes your home directory`),
/// and the part of the code it is about.
pub type Finding = milo_guards_core::Finding<Rule>;

/// The rules code is judged by. Each finding names one.
///
/// This enum is exhaustive on purpose: a rule added here breaks every
/// caller's `match` at compile time, so each caller decides what to do with
/// the new rule. [`Rule::ALL`] lists every rule. Each rule but
/// [`RunProgram`](Rule::RunProgram) has the shell guard's wire name for the
/// same act, and its reasons are the shell guard's for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Deletes or moves away a path beyond the workspace, the workspace
    /// itself, a folder holding it, a key, a startup file, the repository's
    /// history, a path the caller protects (`Paths::protected`, in the
    /// caller's words), or a path only known when the code runs.
    Delete,
    /// Writes over a disk, or deletes one.
    WipeDisk,
    /// Writes to, makes or links to a file beyond the workspace, a key, a
    /// startup file, a file a tool runs on its own (`.envrc`, a CI
    /// workflow), the repository's history, a protected path, or a file only
    /// known when the code runs.
    Overwrite,
    /// Changes the permissions or the owner of a path beyond the workspace or
    /// a sensitive one, or opens a file to everyone (`0o777`).
    Permissions,
    /// Reads a key or a credential: a place core marks as holding one, a
    /// secret the caller named in `Paths::secrets` (in the caller's words), a
    /// disk, what the kernel serves, or a folder that holds the home
    /// directory read all the way down.
    ReadSecret,
    /// Runs code it downloads (`import('https://…')`).
    RunDownloaded,
    /// Starts a program or runs a command in a shell (`subprocess.run([…])`,
    /// `os.system(…)`, `child_process.exec(…)`). This guard does not judge
    /// the program: that is the shell guard's, and a guard never depends on
    /// another. The finding's `target` is the command as a line for the
    /// shell guard, in the machine's shell, which [`target_shell`] says: cmd
    /// on a Windows machine (where `os.system`, `shell=True` and
    /// `child_process.exec` run `cmd.exe`), a POSIX shell on any other.
    ///
    /// - A command run in a shell is the line as the code wrote it.
    /// - A program started without a shell is its words, quoted for that
    ///   shell where it would split or read them as its own.
    /// - Run from another directory, the line starts by moving there
    ///   (`cd -- DIR && `, on Windows `cd /d DIR && `).
    /// - A word only known when the code runs is written as a variable no
    ///   shell sets (`"$UNKNOWN"`), and the program is
    ///   [`Unknown`](Rule::Unknown) too. On Windows such a program has no
    ///   target.
    /// - On Windows a target is only ever words that cmd and the C runtime
    ///   both read as themselves, bare or in plain double quotes for a
    ///   space: a program whose words hold a character cmd reads as its own
    ///   (`& | < > ( ) ^ % ! "`), a word only known when the code runs, code
    ///   that may hand a shell a list, and the other shapes the design page
    ///   lists have no target, and a second `unknown` says so.
    ///
    /// Code that starts a program is never inside the reader's strict
    /// subset, so this finding always comes with an
    /// [`Unknown`](Rule::Unknown) for the code. The target tells a caller
    /// which program, to ask the shell guard about it and add what it finds;
    /// it never makes the code safe: a safe answer for every target does not
    /// mean the code is safe.
    RunProgram,
    /// Code the guard does not read: code the reader does not follow, a path,
    /// a program or a directory only known when the code runs, and code it
    /// does not understand whole in which it found nothing worse.
    Unknown,
    /// Code that cannot be read: longer than [`MAX_LEN`], nested too deeply,
    /// running code inside code too deeply, or that does not parse.
    Unreadable,
}

impl Rule {
    /// Every rule, in the order the design page lists them.
    pub const ALL: [Self; 9] = [
        Self::Delete,
        Self::WipeDisk,
        Self::Overwrite,
        Self::Permissions,
        Self::ReadSecret,
        Self::RunDownloaded,
        Self::RunProgram,
        Self::Unknown,
        Self::Unreadable,
    ];

    /// The rule's stable name on the wire (`delete`, `run_program`). It never
    /// changes once a caller uses it, whatever the variant is called in code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::WipeDisk => "wipe_disk",
            Self::Overwrite => "overwrite",
            Self::Permissions => "permissions",
            Self::ReadSecret => "read_secret",
            Self::RunDownloaded => "run_downloaded",
            Self::RunProgram => "run_program",
            Self::Unknown => "unknown",
            Self::Unreadable => "unreadable",
        }
    }
}

impl milo_guards_core::RuleName for Rule {
    fn name(self) -> &'static str {
        Rule::name(self)
    }
}

/// The shell a [`Rule::RunProgram`] finding's target is a line of: what a
/// caller hands the shell guard with it (its `Shell::Posix` or
/// `Shell::Cmd`).
///
/// Exhaustive on purpose, as [`Rule`] is: a shell added later must break a
/// caller's `match`, so the caller decides how to read its lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetShell {
    /// A POSIX shell (`sh`): the line `os.system` and `child_process.exec`
    /// run on any machine but Windows.
    Posix,
    /// cmd (`cmd.exe`): the line they run on Windows.
    Cmd,
}

/// The shell the targets of [`Rule::RunProgram`] findings are lines of, on
/// the machine `paths` describe: [`TargetShell::Cmd`] on Windows (a Windows
/// home directory, as core's path model tells the machines apart),
/// [`TargetShell::Posix`] on any other.
///
/// ```
/// use milo_guards_script::{target_shell, Paths, TargetShell};
///
/// let posix = Paths::new("/home/me/work/repo", "/home/me", ["/home/me/work/repo"]);
/// assert_eq!(target_shell(&posix), TargetShell::Posix);
/// let windows = Paths::new(r"C:\Users\me\dev\repo", r"C:\Users\me", [r"C:\Users\me\dev\repo"]);
/// assert_eq!(target_shell(&windows), TargetShell::Cmd);
/// ```
#[must_use]
pub fn target_shell(paths: &Paths) -> TargetShell {
    match milo_guards_core::Resolver::new(paths).flavour() {
        milo_guards_core::Flavour::Windows => TargetShell::Cmd,
        milo_guards_core::Flavour::Posix => TargetShell::Posix,
    }
}

/// The longest code judged, in bytes: the code reader's limit, and the
/// shell guard's for a line. Longer code is [`Rule::Unreadable`].
pub const MAX_LEN: usize = milo_guards_code::MAX_LEN;

/// Judge `code`, written in `language`, run from the working directory of
/// `paths` with the directories in it.
///
/// ```
/// use milo_guards_script::{judge, Language, Paths, Rule, Secret};
///
/// let paths = Paths::new("/home/me/work/app", "/home/me", ["/home/me/work/app"])
///     .with_secrets([Secret::file("/home/me/work/app/.env", "the project's environment file")]);
/// let assessment = judge(Language::Python, "print(open('.env').read())", &paths);
/// assert_eq!(assessment.findings()[0].rule, Rule::ReadSecret);
/// assert_eq!(assessment.findings()[0].reason, "reads the project's environment file");
///
/// // Code that does not parse is unreadable, never safe.
/// let assessment = judge(Language::JavaScript, "console.log(", &paths);
/// assert_eq!(assessment.findings()[0].rule, Rule::Unreadable);
/// ```
#[must_use = "the assessment is the answer: it says whether the code is safe"]
pub fn judge(language: Language, code: &str, paths: &Paths) -> Assessment {
    let mut findings = judge::judge(language, code, paths).findings;
    // With a link, a drive mount or a Windows home named, the code is also
    // judged on each other set of the paths (`Paths::also_judged_on`), and
    // every finding of each is kept: naming what only the disk can say never
    // makes an answer less serious.
    for other in paths.also_judged_on() {
        for finding in judge::judge(language, code, &other).findings {
            if !findings.contains(&finding) {
                findings.push(finding);
            }
        }
    }
    assessed(findings)
}

/// The answer for `findings`: safe when there are none.
fn assessed(findings: Vec<Finding>) -> Assessment {
    if findings.is_empty() {
        Assessment::Safe
    } else {
        Assessment::Risky(findings)
    }
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
