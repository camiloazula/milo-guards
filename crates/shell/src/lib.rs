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
//!    Python and JavaScript given inline (`python3 -c`, `node -e`, a
//!    here-document fed to `python3 -`) are read with their own grammars, and
//!    what they delete, write and run is judged like the same shell command.
//! 2. **Detect** with rules that read a unit's program, flags, operands and
//!    redirects, never the raw text, and judge each path by where it
//!    resolves against [`Paths`].
//! 3. **Combine**: the line is safe only when no unit is risky, and a risky
//!    line carries every finding.
//!
//! [`effect`] answers a second question from the same split and findings:
//! does the line only read? It is [`Effect::ReadsOnly`] when every unit is a
//! known reader, and then says by a [`Reach`] whether what it reads stays in
//! the workspace; [`Effect::Changes`] when one writes, and
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
mod explain;
mod inline;
mod launch;
mod path;
mod posix;
mod powershell;
mod startup;
mod unit;

pub use effect::{Effect, How, Reach, ReadPath};
pub use explain::{
    ArgExplanation, ArgKind, Explanation, PipelineStage, RedirectExplanation, UnitExplanation,
};
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
    /// Reads a key or a credential: a file a program the guard knows opens,
    /// or a `<` redirect, that lands on a place core marks as holding one,
    /// as the file guard's rule of the same name does for the same file; also
    /// a disk, and what the kernel serves. Not the repository's history, not
    /// a shell startup file, and not a file named only when the line runs.
    /// `effect` still calls such a line reads-only, as it does for
    /// [`Elevated`](Rule::Elevated): the line only reads.
    ReadSecret,
    /// Runs as root or administrator.
    Elevated,
    /// Runs a script it downloads.
    RunDownloaded,
    /// Runs commands read from its input (a pipe, a here-document), which
    /// the line does not show.
    RunInput,
    /// Shuts the computer down, restarts it, or stops every process.
    StopSystem,
    /// Sends a key, a credential or the environment off the machine.
    SendSecret,
    /// Deletes data in a database.
    DropData,
    /// Deletes containers, cluster objects, cloud resources or an
    /// infrastructure stack.
    DestroyResources,
    /// Runs a program or a script known only when it runs.
    Unknown,
    /// The line, or part of it, cannot be read.
    Unreadable,
}

impl Rule {
    /// Every rule, in the order the design page lists them.
    pub const ALL: [Self; 18] = [
        Self::Delete,
        Self::WipeDisk,
        Self::Overwrite,
        Self::GitDiscard,
        Self::GitRemote,
        Self::GitHistory,
        Self::Permissions,
        Self::SystemSettings,
        Self::ReadSecret,
        Self::Elevated,
        Self::RunDownloaded,
        Self::RunInput,
        Self::StopSystem,
        Self::SendSecret,
        Self::DropData,
        Self::DestroyResources,
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
            Self::ReadSecret => "read_secret",
            Self::Elevated => "elevated",
            Self::RunDownloaded => "run_downloaded",
            Self::RunInput => "run_input",
            Self::StopSystem => "stop_system",
            Self::SendSecret => "send_secret",
            Self::DropData => "drop_data",
            Self::DestroyResources => "destroy_resources",
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
/// says the split also keeps what only [`effect`] reads. [`classify`],
/// [`effect`] and [`explain`] each take their answer from it, so they cannot
/// disagree about what the units are or what they found.
struct Reading {
    split: unit::Split,
    judged: detect::Judged,
    resolver: path::Resolver,
}

impl Reading {
    fn new(command: &str, shell: Shell, paths: &Paths, effect: bool) -> Self {
        let split = unit::split(command, shell, effect);
        let mut resolver = path::Resolver::new(paths);
        if effect {
            resolver.keep(paths);
        }
        let judged = detect::findings(&split, &resolver);
        Self {
            split,
            judged,
            resolver,
        }
    }
}

/// Judge `command`, run by `shell` with the directories in `paths`.
#[must_use = "the assessment is the answer: it says whether the line is safe"]
pub fn classify(command: &str, shell: Shell, paths: &Paths) -> Assessment {
    let findings = Reading::new(command, shell, paths, false).judged.found;
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
/// `cat ~/.ssh/id_ed25519` is [`Effect::ReadsOnly`]). A line that only reads
/// says where it reads: [`Reach::Workspace`] when every place is inside a
/// workspace folder, a temporary file or the null device, and
/// [`Reach::Beyond`] when any is not. It comes from the same
/// split as `classify`, so what is a unit, a wrapper or a nested script is
/// the same in both, and a caller reads both answers. What cannot be read
/// is [`Effect::Unknown`], never reads-only.
///
/// ```
/// use milo_guards_shell::{classify, effect, Effect, Paths, Reach, Shell};
///
/// let paths = Paths::new("/work/app", "/home/me", ["/work/app"]);
/// let stays = Effect::ReadsOnly(Reach::Workspace);
/// assert_eq!(effect("git status && git diff", Shell::Posix, &paths), stays);
/// // It only reads, and what it reads is not the project.
/// let beyond = Effect::ReadsOnly(Reach::Beyond);
/// assert_eq!(effect("cat ~/.ssh/id_ed25519", Shell::Posix, &paths), beyond);
/// assert_eq!(effect("ls", Shell::Posix, &Paths::new("/etc", "/home/me", ["/work/app"])), beyond);
/// // Safe, and it changes the disk.
/// assert!(classify("mkdir build", Shell::Posix, &paths).is_safe());
/// assert_eq!(effect("mkdir build", Shell::Posix, &paths), Effect::Changes);
/// // A program only known when it runs is not reads-only.
/// assert_eq!(effect("$CMD", Shell::Posix, &paths), Effect::Unknown);
/// ```
#[must_use = "the effect is the answer: it says whether the line only reads"]
pub fn effect(command: &str, shell: Shell, paths: &Paths) -> Effect {
    let reading = Reading::new(command, shell, paths, true);
    effect::of(&reading.split, &reading.judged.found, &reading.resolver)
}

/// Show how `command`, run by `shell` with the directories in `paths`, was
/// read: every program it runs as the rules saw it (the program and its
/// arguments, where each lands, the folder it runs from, the wrappers taken
/// off, the shell and nesting it came from, its place in a pipeline) and the
/// findings each produced, beside the line's own.
///
/// It is [`classify`] with the reasoning kept: both take their answer from
/// one reading, so [`Explanation::findings`] is what `classify` reports and
/// [`Explanation::assessment`] is its answer. `Display` prints a short
/// indented tree a person can read in a terminal or paste into an issue;
/// building it prints nothing.
///
/// ```
/// use milo_guards_shell::{explain, Paths, Shell};
///
/// let paths = Paths::new("/work/app", "/home/me", ["/work/app"]);
/// let explanation = explain("sudo rm -rf ~", Shell::Posix, &paths);
/// let unit = &explanation.units[0];
/// assert_eq!(unit.program, "rm");
/// assert_eq!(unit.wrappers, ["sudo"]);
/// assert_eq!(unit.args[1].resolved.as_deref(), Some("your home directory"));
/// assert!(!explanation.assessment().is_safe());
/// println!("{explanation}");
/// ```
#[must_use = "the explanation is the answer: it shows how the line was read"]
pub fn explain(command: &str, shell: Shell, paths: &Paths) -> Explanation {
    let reading = Reading::new(command, shell, paths, false);
    explain::explanation(command, shell, &reading)
}

/// The places `command`, run by `shell` with the directories in `paths`,
/// reads and how each is read, when [`effect`] says it only reads; `None` for
/// any other line.
///
/// A guard never touches the disk, so [`effect`] places each read by how it
/// is spelled, and a symbolic link in the workspace that points out of it
/// (`link -> ~/.ssh`, then `cat link/id_rsa`) is [`Reach::Workspace`]. A caller
/// that can check the disk needs the places the line reads, and how the
/// program reaches from each: a pattern is expanded by the shell, a recursive
/// search walks a folder, and either can cross a link that a bare path would
/// not show. This is the list [`effect`] judged, from the same reading, not a
/// second one.
///
/// What it holds, as [`effect`] reads the line: every file operand and the
/// source of every `<` redirect, the folder a lister lists, the target of a
/// `cd`, the working directory when a reader with no file operand reads it
/// without being told (`ls`, `rg TODO`, `git status`), the root of a deep
/// read, and for `git` the repository at the working directory or at the
/// folders `-C` chains. A git revision or pathspec is listed as a path too, as
/// `effect` places it (`git show HEAD:a.rs` also lists `a.rs`, from the
/// working directory and from every workspace folder). A line run after a
/// `cd` reads from where the `cd` went.
///
/// Every [`ReadPath::path`] is absolute, spelled as the guard resolves it
/// (`~` is the home directory, `.` and `..` are applied, a relative path starts
/// at the working directory or at where a `cd` went), and nothing is read from
/// the disk, so a link is not followed. The list is sorted and holds each
/// entry once, so the answer is the same every time. A read that is not a
/// place on a disk (the null device, a registry hive, a path on another
/// drive's own working directory) has no path and is not listed; [`effect`]
/// has judged it by its place. A path in a temporary folder is listed like any
/// other: it is [`Reach::Workspace`] by that rule, not because it is inside the
/// workspace.
///
/// Each entry says how it is read ([`How`]), which says what a caller checks:
///
/// - [`How::Exact`]: one path. Canonicalize it (a path that does not exist is
///   resolved by its nearest existing ancestor, with the rest of the names put
///   back).
/// - [`How::Glob`]: a pattern the shell expands, as the fixed folder and the
///   rest of the pattern. Expand it on disk the way the shell does, and
///   canonicalize the folder and every match: the shell crosses a link while it
///   expands (`cat src/*/x.rs` with `src/a -> ~`).
/// - [`How::Tree`]: a folder the program walks, or whose names it hands to a
///   program that opens them (`ls src | xargs cat`, `find src -exec cat {} +`).
///   Canonicalize the root. When `follows_links` is `false` (`grep -r`, `rg`,
///   `find`, `ls -R`, `du`, `git`, given only flags known not to follow links)
///   that is the whole check. When it is `true` (`grep -R`, `rg -L`, `find -L`,
///   `ls -RL`, `du -L`, a walk whose names are opened, any other flag, any
///   reader the guard does not know to stay out of links) a link anywhere below the root
///   can lead out, and a caller may simply treat the line as reading beyond
///   the workspace.
///
/// Treat the line as reading beyond the workspace when anything a check finds
/// leaves it. The workspace folders are what the caller compares with, after
/// canonicalizing them too, and the temporary folders [`effect`] allows: on
/// macOS `/tmp` is `/private/tmp` and `/var/folders` is `/private/var/folders`.
///
/// ```
/// use std::path::PathBuf;
/// use milo_guards_shell::{effect_paths, How, Paths, ReadPath, Shell};
///
/// let paths = Paths::new("/work/app", "/home/me", ["/work/app"]);
/// let exact = |path: &str| ReadPath { path: PathBuf::from(path), how: How::Exact };
/// let read = |line| effect_paths(line, Shell::Posix, &paths);
/// assert_eq!(read("cat link/id_rsa"), Some(vec![exact("/work/app/link/id_rsa")]));
/// assert_eq!(read("cat ~/.ssh/config"), Some(vec![exact("/home/me/.ssh/config")]));
/// // A pattern: the folder it expands in, and the rest of it.
/// let glob = ReadPath { path: PathBuf::from("/work/app"), how: How::Glob("*.rs".into()) };
/// assert_eq!(read("cat *.rs"), Some(vec![glob]));
/// // A walk, and whether it opens what it finds through links.
/// let walk = |path: &str, follows_links| ReadPath {
///     path: PathBuf::from(path),
///     how: How::Tree { follows_links },
/// };
/// assert_eq!(read("rg TODO src"), Some(vec![walk("/work/app/src", false)]));
/// assert_eq!(read("grep -R TODO src"), Some(vec![walk("/work/app/src", true)]));
/// assert_eq!(read("ls src | xargs cat"), Some(vec![walk("/work/app/src", true)]));
/// // A line that changes something, or cannot be read, has no list.
/// assert_eq!(read("mkdir x"), None);
/// assert_eq!(read("$CMD"), None);
/// ```
#[must_use = "the paths are the answer: they are what the line reads"]
pub fn effect_paths(command: &str, shell: Shell, paths: &Paths) -> Option<Vec<ReadPath>> {
    let reading = Reading::new(command, shell, paths, true);
    effect::paths(&reading.split, &reading.judged.found, &reading.resolver)
}
