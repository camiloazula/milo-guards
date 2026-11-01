//! Reads a shell command line and says whether it is safe to run without
//! asking, or risky and why: [`classify`]; and whether it only reads,
//! changes something or cannot be told: [`effect`].
//!
//! It works in three steps:
//!
//! 1. **Split** the line into units, one per program it runs, with the
//!    grammar of the shell that runs it ([`Shell`]). Chains (`&&`, `;`),
//!    pipes, substitutions (`$(…)`), loops and blocks are walked, every
//!    branch whether or not it would run. Wrappers (`sudo`, `env`, `xargs`,
//!    `find -exec`, `Start-Process`, `start`) are taken off, and a shell
//!    started with a script (`bash -c`, `eval`, `cmd /c`,
//!    `powershell -Command`, `Invoke-Expression`) has that script split in
//!    its own grammar.
//! 2. **Detect** with rules that read a unit's program, flags, operands and
//!    redirects, never the raw text, and judge each path by where it
//!    resolves against [`Paths`].
//! 3. **Combine**: the line is safe only when no unit is risky, and a risky
//!    line carries every finding.
//!
//! [`effect`] answers a second question from the same split and findings:
//! does the line only read? It is [`Effect::ReadsOnly`] when every unit is a
//! known reader, [`Effect::Changes`] when one writes, and
//! [`Effect::Unknown`] when anything is not understood.
//!
//! What cannot be read is risky: a program or a script known only when it
//! runs, a line the grammar cannot parse, shells nested past a limit.
//! Nothing here touches the file system or the environment: paths are
//! resolved by their spelling, against the directories the caller passes,
//! the same way on every host, so a Windows line is judged on macOS as it
//! would be on Windows.

mod cmd;
mod detect;
mod dotglob;
mod effect;
mod launch;
mod path;
mod posix;
mod powershell;
mod startup;
mod unit;

pub use effect::Effect;
pub use milo_guards_core::{Paths, Protected, ProtectedKind};

/// The shell that runs the line, whose grammar splits it.
///
/// `#[non_exhaustive]`: a shell with a grammar of its own may be added, so a
/// caller's `match` needs a fallback arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Shell {
    /// `sh`, `bash`, `zsh` and the shells that share their syntax.
    Posix,
    /// Windows PowerShell and PowerShell 7 (`pwsh`).
    PowerShell,
    /// The Windows command prompt (`cmd.exe`).
    Cmd,
}

impl Shell {
    /// The shell a program runs lines in, by its name or path (`$SHELL`,
    /// `/bin/zsh`, `pwsh.exe`): the POSIX shells, PowerShell and cmd.
    /// `None` for a shell with no grammar here (fish, csh); reading such a
    /// line as [`Shell::Posix`] is still fail-safe, since what the grammar
    /// cannot parse comes back risky.
    #[must_use]
    pub fn for_program(program: &str) -> Option<Self> {
        let name = program
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(program)
            .to_ascii_lowercase();
        let name = name.strip_suffix(".exe").unwrap_or(&name);
        match name {
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "mksh" | "ash" | "yash" => Some(Self::Posix),
            "powershell" | "pwsh" => Some(Self::PowerShell),
            "cmd" => Some(Self::Cmd),
            _ => None,
        }
    }
}

/// What [`classify`] concluded about a command line: safe, or risky with
/// every finding.
pub type Assessment = milo_guards_core::Assessment<Rule>;

/// One reason a line is risky: the rule that found it, what it would do in
/// a few words a permission prompt can show (`deletes your home directory`),
/// and the argument it is about, as written, where there is one (`~`).
pub type Finding = milo_guards_core::Finding<Rule>;

/// The rules a line is judged by. Each finding names one.
///
/// This enum is exhaustive on purpose: a rule added here breaks every
/// caller's `match` at compile time, so each caller decides what to do with
/// the new rule rather than meeting it as an unhandled case at run time.
/// [`Rule::ALL`] lists every rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Deletes files beyond the workspace, the workspace itself, a sensitive
    /// file, or a path known only when it runs.
    Delete,
    /// Formats, repartitions or writes over a disk.
    WipeDisk,
    /// Writes into a file beyond the workspace or a sensitive one.
    Overwrite,
    /// Throws away work git cannot give back: uncommitted changes,
    /// untracked files, stashes, unmerged branches.
    GitDiscard,
    /// Rewrites or deletes branches on a remote.
    GitRemote,
    /// Rewrites the repository's history or what git keeps to recover it.
    GitHistory,
    /// Changes permissions or ownership beyond the workspace, or opens files
    /// to everyone.
    Permissions,
    /// Changes how the system runs: the registry, boot settings, restore
    /// points, accounts, the firewall, antivirus, script policy.
    SystemSettings,
    /// Runs as root or administrator.
    Elevated,
    /// Runs a script it downloads.
    RunDownloaded,
    /// Runs commands read from its input (a pipe, a here-document), which
    /// the line does not show.
    RunInput,
    /// Shuts the computer down, restarts it, or stops every process.
    StopSystem,
    /// Runs a program or a script known only when it runs.
    Unknown,
    /// The line, or part of it, cannot be read.
    Unreadable,
}

impl Rule {
    /// Every rule, in the order the design page lists them.
    pub const ALL: [Self; 14] = [
        Self::Delete,
        Self::WipeDisk,
        Self::Overwrite,
        Self::GitDiscard,
        Self::GitRemote,
        Self::GitHistory,
        Self::Permissions,
        Self::SystemSettings,
        Self::Elevated,
        Self::RunDownloaded,
        Self::RunInput,
        Self::StopSystem,
        Self::Unknown,
        Self::Unreadable,
    ];

    /// The rule's stable name on the wire (`delete`, `wipe_disk`). It never
    /// changes once a caller uses it, whatever the variant is called in
    /// code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::WipeDisk => "wipe_disk",
            Self::Overwrite => "overwrite",
            Self::GitDiscard => "git_discard",
            Self::GitRemote => "git_remote",
            Self::GitHistory => "git_history",
            Self::Permissions => "permissions",
            Self::SystemSettings => "system_settings",
            Self::Elevated => "elevated",
            Self::RunDownloaded => "run_downloaded",
            Self::RunInput => "run_input",
            Self::StopSystem => "stop_system",
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

/// A line read once: split into units and judged by the rules. `effect`
/// says the split also keeps what only [`effect`] reads. [`classify`]
/// and [`effect`] each take their answer from it, so they cannot disagree
/// about what the units are.
struct Reading {
    split: unit::Split,
    findings: Vec<Finding>,
    resolver: path::Resolver,
}

impl Reading {
    fn new(command: &str, shell: Shell, paths: &Paths, effect: bool) -> Self {
        let split = unit::split(command, shell, effect);
        let resolver = path::Resolver::new(paths);
        let findings = detect::findings(&split, &resolver);
        Self {
            split,
            findings,
            resolver,
        }
    }
}

/// Judge `command`, run by `shell` with the directories in `paths`.
#[must_use = "the assessment is the answer: it says whether the line is safe"]
pub fn classify(command: &str, shell: Shell, paths: &Paths) -> Assessment {
    let findings = Reading::new(command, shell, paths, false).findings;
    if findings.is_empty() {
        Assessment::Safe
    } else {
        Assessment::Risky(findings)
    }
}

/// Say whether `command`, run by `shell` with the directories in `paths`,
/// only reads, changes something, or cannot be told.
///
/// It is a second answer beside [`classify`], not a rule: safe and reads
/// only are different things (`mkdir build` is safe and [`Effect::Changes`];
/// `cat ~/.ssh/id_ed25519` is [`Effect::ReadsOnly`]). It comes from the same
/// split as `classify`, so what is a unit, a wrapper or a nested script is
/// the same in both, and a caller reads both answers. What cannot be read
/// is [`Effect::Unknown`], never reads-only.
///
/// ```
/// use milo_guards_shell::{classify, effect, Effect, Paths, Shell};
///
/// let paths = Paths::new("/work/app", "/home/me", ["/work/app"]);
/// assert_eq!(effect("git status && git diff", Shell::Posix, &paths), Effect::ReadsOnly);
/// // Safe, and it changes the disk.
/// assert!(classify("mkdir build", Shell::Posix, &paths).is_safe());
/// assert_eq!(effect("mkdir build", Shell::Posix, &paths), Effect::Changes);
/// // A program only known when it runs is not reads-only.
/// assert_eq!(effect("$CMD", Shell::Posix, &paths), Effect::Unknown);
/// ```
#[must_use = "the effect is the answer: it says whether the line only reads"]
pub fn effect(command: &str, shell: Shell, paths: &Paths) -> Effect {
    let reading = Reading::new(command, shell, paths, true);
    effect::of(&reading.split, &reading.findings, &reading.resolver)
}
