//! A command line split into units, one per program it runs, whichever
//! grammar split it; and the helpers that read a unit's arguments.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::rc::Rc;

use crate::dotglob;
use crate::effect::Kind;
use crate::extended;
use crate::startup::{self, Startup};
use crate::{Finding, Rule, Shell};

/// One argument as the program receives it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Arg {
    /// Its value is in the text: `target`, `~/x`, `"a b"`.
    Known(String),
    /// Only known when it runs (`$VAR`, `$(…)`, `%X%`): its source text.
    Unknown(String),
    /// A string known except for the expansions in it, which stand as they
    /// are written: `"rm -rf $d"` is the text `rm -rf $d` and `"$x"` is
    /// `$x`. Not a value, but its text can be read as a script, whose own
    /// grammar then finds what it expands.
    Template {
        /// The text, with each expansion as written.
        text: String,
        /// The argument as written, quotes and all. A boxed `str`, not a
        /// `String`, so that with `runs` an `Arg` stays the size of two
        /// strings: the walk of a deeply nested line holds many on the
        /// stack, and a bigger one overflows it before the depth limit.
        source: Box<str>,
        /// Whether an expansion in it runs a command (`$(…)`, a backtick):
        /// it prints what it likes, where a variable stands for a value.
        runs: bool,
    },
    /// What the previous stage of its pipeline hands it: `xargs`, a
    /// cmdlet's pipeline input, `$_`.
    Input,
    /// PowerShell's `$null`, the null value: handed to a file parameter it is
    /// the null device, or no value at all. Its own form, since no quoted
    /// literal (`'$null'`, a file named that) is it; in cmd it is a file name,
    /// and in a POSIX shell the variable `null`.
    Null,
}

impl Arg {
    pub(crate) fn known(&self) -> Option<&str> {
        match self {
            Self::Known(text) => Some(text),
            Self::Unknown(_) | Self::Template { .. } | Self::Input | Self::Null => None,
        }
    }

    /// Whether the value is only known when it runs, however much of its
    /// text is readable.
    pub(crate) fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_) | Self::Template { .. })
    }

    /// The value, or the source text of what is only known when it runs.
    pub(crate) fn text(&self) -> &str {
        match self {
            Self::Known(text) | Self::Unknown(text) => text,
            Self::Template { source, .. } => source,
            Self::Input => "<input>",
            Self::Null => "$null",
        }
    }
}

/// Where a unit sits in a pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stage {
    pub(crate) pipeline: usize,
    pub(crate) index: usize,
}

/// What a unit reads its commands from, when it is a shell or an
/// interpreter that reads them from its input rather than an argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reads {
    Nothing,
    /// A shell reading commands from its input.
    Shell,
    /// A language interpreter reading code from its input.
    Interpreter,
}

/// One program the line runs.
#[derive(Debug, Clone, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate fact the walker learned about the unit; none combine into a state"
)]
pub(crate) struct Unit {
    /// The shell whose syntax its arguments are in.
    pub(crate) shell: Shell,
    pub(crate) program: Arg,
    pub(crate) args: Vec<Arg>,
    /// The wrappers taken off in front of it, by name: `sudo`, `env`.
    pub(crate) wrappers: Vec<String>,
    pub(crate) stage: Option<Stage>,
    pub(crate) reads: Reads,
    /// What a here-document or here-string hands the program as its input:
    /// the text, when it is plain text, and an unknown when the input is
    /// read from a file or the text is only known when it runs. `None` for
    /// a program whose input is not redirected.
    pub(crate) stdin: Option<Arg>,
    /// Where an earlier `cd` in the line moved to, when one did: relative
    /// paths resolve from there.
    pub(crate) dir: Option<Arg>,
    /// The other folders the line may be in when it runs, because a `cd`
    /// before it may not have run (see [`Split::elsewhere`]): a script it
    /// runs may be the file of that name in any of them.
    pub(crate) elsewhere: Vec<Option<Arg>>,
    /// The folders the line is still in when a plain `cd` before it failed
    /// (see [`Split::stayed`]): a script it runs may be the file of that
    /// name in any of them.
    pub(crate) stayed: Vec<Option<Arg>>,
    /// Whether the plain `cd`s before it that may have failed left the line
    /// in more folders than the guard follows (see [`Split::adrift`]): it
    /// may then be in a folder only known when it runs.
    pub(crate) adrift: bool,
    /// Whether it sits in a loop or a function body that may run it again
    /// from another folder (see [`Split::end_body`]): a pass of the loop
    /// after the first starts where the last left the line, and a call
    /// where the line is when it is made. Its paths are judged from a folder
    /// only known when it runs too (see [`Unit::again`]).
    pub(crate) rerun: bool,
    /// Whether an earlier unit in the line turned on a shell option that
    /// lets a wildcard match a leading dot (`shopt -s dotglob`, `setopt
    /// globdots`, a non-empty `GLOBIGNORE`): its patterns can match `.git`.
    pub(crate) hidden: bool,
    /// The files `BASH_ENV` names for this unit alone (`BASH_ENV=f cmd`,
    /// `env BASH_ENV=f cmd`): a bash it starts runs each before its own
    /// script. The files the line sets for every shell it starts are in
    /// [`Split::startup`] (see [`crate::startup`]).
    pub(crate) startup: Rc<Vec<Startup>>,
    /// Whether it sits in a loop or a function body, which runs it again
    /// with other values: a variable it reads can name a different thing
    /// each time, so every one of them together.
    pub(crate) repeated: bool,
    /// Whether the script it runs is a download (`Invoke-Expression` given
    /// `(iwr url)`), which only runs when it does.
    pub(crate) downloaded: bool,
    /// Whether it may move a PowerShell session to a place the guard cannot
    /// follow: a script block or a script run by a name only known when it
    /// runs (`& $b`, `. $b`) may hold a `cd`, and the session has one
    /// location, whatever scope the block runs in.
    pub(crate) relocates: bool,
    /// The `Get-Process` listings written inside the arguments of a
    /// `Stop-Process` (`-InputObject (Get-Process)`), which it stops.
    pub(crate) listings: Vec<Listing>,
    /// Whether a value given to a `Stop-Process` in a `ForEach-Object` block
    /// is built on `$_` into something other than the item or one of its
    /// own members (`$_.Parent`, `$_ + 1`): not the processes the pipeline
    /// hands it.
    pub(crate) unread_item: bool,
    /// For a `Stop-Process`, whether each argument holds a `Get-Process`
    /// listing, which the listing rules judge (`-Id (Get-Process node).Id`):
    /// in step with `args`, and empty for any other unit, or one that
    /// lost them, in which no argument counts as read this way.
    pub(crate) listed: Vec<bool>,
    /// The values the line gives the variables a program reads as its own
    /// arguments where it runs, by name (see [`Split::argument_variables`]):
    /// `TF_CLI_ARGS` and `TF_CLI_ARGS_<command>`, which terraform reads as
    /// arguments of its command, `npm_config_call`, the command `npx`
    /// runs, and the editor, pager and shell `psql` runs (`PAGER`). Shared with the line's, so a long value is not copied for
    /// each program.
    pub(crate) argument_variables: Rc<Vec<(String, Arg)>>,
    /// How many levels deep the script it came from is nested: `0` for the
    /// line itself, one more for each `bash -c`, `eval` or `cmd /c`, and one
    /// more for a part of the line the grammar reads again (what follows the
    /// `&&` in cmd's `set X=1 && del y`, the stage after PowerShell's `--%`).
    /// It is what the depth limit counts.
    pub(crate) depth: usize,
    /// For a PowerShell unit the walk reads from the grammar, the variables
    /// its arguments read, by the grammar's variable nodes (`$k`, `"x$k"`, a
    /// splat `@p`; see [`crate::powershell::variables`]). `None` for a unit
    /// of another shell, or one the guard makes up for a .NET call, whose
    /// variables are read from its arguments' text (see [`Unit::variables`]).
    pub(crate) names: Option<Vec<String>>,
}

/// A `Get-Process` written inside an argument: its own arguments, and what
/// follows it before the value is used.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Listing {
    pub(crate) args: Vec<Arg>,
    pub(crate) between: Vec<Between>,
}

/// A stage between a `Get-Process` listing and the `Stop-Process` it feeds.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Between {
    /// `Where-Object`, with its arguments (a block that is a simple
    /// comparison is read into `Name -eq value`).
    Where(Vec<Arg>),
    /// `Sort-Object`, and a `Select-Object` that only picks (see
    /// [`Between::select`]): some of the same processes.
    Narrows,
    /// Anything else, which may hand on processes the listing did not.
    Other,
}

impl Between {
    /// A `Select-Object` stage given `args`: it keeps some of the same
    /// processes, unless it is given `-ExpandProperty` (any prefix of three
    /// letters or more, written `-exp` or `-exp:Parent`) or a calculated
    /// property (a hashtable or a script block), which hand on other
    /// objects, such as a process's parent.
    pub(crate) fn select(args: &[Arg]) -> Self {
        let hands_on = args.iter().any(|arg| {
            let text = arg.text().trim_start();
            if matches!(arg, Arg::Known(_)) {
                let name = text
                    .strip_prefix('-')
                    .and_then(|name| name.split(':').next());
                name.is_some_and(|name| {
                    name.len() >= 3 && "expandproperty".starts_with(&name.to_ascii_lowercase())
                })
            } else {
                text.starts_with("@{") || text.starts_with('{')
            }
        });
        if hands_on {
            Self::Other
        } else {
            Self::Narrows
        }
    }
}

/// Where and how a unit's paths are read: the folder an earlier `cd` moved
/// to, and whether its wildcards match hidden names.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Scope<'a> {
    pub(crate) dir: Option<&'a Arg>,
    pub(crate) hidden: bool,
}

impl Unit {
    pub(crate) fn new(shell: Shell, program: Arg, args: Vec<Arg>, stage: Option<Stage>) -> Self {
        Self {
            shell,
            program,
            args,
            wrappers: Vec::new(),
            stage,
            reads: Reads::Nothing,
            stdin: None,
            dir: None,
            elsewhere: Vec::new(),
            stayed: Vec::new(),
            adrift: false,
            rerun: false,
            hidden: false,
            startup: Rc::default(),
            repeated: false,
            downloaded: false,
            relocates: false,
            listings: Vec::new(),
            unread_item: false,
            listed: Vec::new(),
            argument_variables: Rc::default(),
            depth: 0,
            names: None,
        }
    }

    /// The variables the unit's arguments read: [`Unit::names`] when the
    /// grammar gave them, and otherwise the ones its arguments that are only
    /// known when it runs name.
    pub(crate) fn variables(&self) -> Vec<String> {
        match &self.names {
            Some(names) => names.clone(),
            None => self
                .args
                .iter()
                .filter(|arg| arg.is_unknown())
                .flat_map(|arg| referenced_in(arg.text(), self.shell))
                .collect(),
        }
    }

    pub(crate) fn scope(&self) -> Scope<'_> {
        Scope {
            dir: self.dir.as_ref(),
            hidden: self.hidden,
        }
    }

    /// Every other folder the line may be in when this unit runs, besides
    /// [`Self::dir`], each once: where a `cd` before it that may not have run
    /// ([`Self::elsewhere`]) or may have failed ([`Self::stayed`]) left the
    /// line, a folder only known when it runs past the most the guard
    /// follows, and the one a loop or a function body may run it again from
    /// ([`Self::again`]). Its paths are judged from each of them too.
    pub(crate) fn others(&self) -> Vec<Option<Arg>> {
        let mut folders = self.moved_off();
        if let Some(again) = self.again_from(&folders) {
            folders.push(Some(again));
        }
        folders
    }

    /// [`Self::others`] but [`Self::again`]: the folders a `cd` before it
    /// that may not have run or may have failed left the line in.
    pub(crate) fn moved_off(&self) -> Vec<Option<Arg>> {
        others(
            self.dir.as_ref(),
            &self.elsewhere,
            &self.stayed,
            self.adrift,
        )
    }

    /// The folder only known when it runs that a loop or a function body
    /// may run it again from (see [`Self::rerun`]), unless the unit is
    /// judged from one already.
    pub(crate) fn again(&self) -> Option<Arg> {
        self.again_from(&self.moved_off())
    }

    /// [`Self::again`], given what [`Self::moved_off`] gives.
    fn again_from(&self, moved_off: &[Option<Arg>]) -> Option<Arg> {
        let again = Arg::Unknown(AGAIN.to_string());
        (self.rerun
            && !same_folder(self.dir.as_ref(), Some(&again))
            && !moved_off
                .iter()
                .any(|folder| same_folder(folder.as_ref(), Some(&again))))
        .then_some(again)
    }

    /// This unit as it runs with the line in `dir`, one of
    /// [`Self::others`]: judged from there alone, so a run of a file the
    /// line wrote, which is judged from every folder already, is not read
    /// again.
    pub(crate) fn in_folder(&self, dir: Option<Arg>) -> Self {
        Self {
            dir,
            elsewhere: Vec::new(),
            stayed: Vec::new(),
            adrift: false,
            rerun: false,
            ..self.clone()
        }
    }

    /// The program's name for the rules, when it is known: the last part of
    /// its path; for Windows, in lower case and without `.exe`; for
    /// PowerShell, its cmdlet's name when it is an alias.
    pub(crate) fn key(&self) -> Option<String> {
        self.program.known().map(|program| key(program, self.shell))
    }
}

/// The functions that [`Split::reaching`] keeps, by name, and the first unit
/// that may call each name, so that which functions a unit may call, and
/// whether a name was called before, are lookups and not a read of every
/// function or every earlier unit.
///
/// A unit may call a function when its program is the function's name, or
/// its path ends in it (the key is in lower case, so a function whose name
/// differs only in case counts too).
#[derive(Debug, Default)]
struct Names {
    /// The functions of each name as written. A later definition that surely
    /// runs in the line's own shell replaces the earlier ones, as it does in
    /// the shell, so that a name defined many times is one entry and not as
    /// many as there are definitions; one that may not run (or runs in a
    /// shell of its own) is kept beside them, since the earlier one may be
    /// the function a call reaches.
    exact: HashMap<String, Vec<usize>>,
    /// The functions by their name in lower case.
    lower: HashMap<String, Vec<usize>>,
    /// The first unit whose program is the name as written, and the first
    /// whose key is the name.
    first_exact: HashMap<String, usize>,
    first_key: HashMap<String, usize>,
}

impl Names {
    /// Note that the function `name` is `at` in [`Split::reaching`]. When
    /// `replaces`, the definition surely runs in the line's own shell, so it
    /// takes the place of the earlier functions of the same name; otherwise
    /// it is kept beside them.
    fn add(&mut self, name: &str, at: usize, replaces: bool) {
        let earlier = self.exact.entry(name.to_string()).or_default();
        let replaced = if replaces {
            std::mem::take(earlier)
        } else {
            Vec::new()
        };
        earlier.push(at);
        let lower = self.lower.entry(name.to_ascii_lowercase()).or_default();
        lower.retain(|index| !replaced.contains(index));
        lower.push(at);
    }

    /// Note that the unit `unit` is the one at `at`, and give the functions
    /// it may call, each once and in the order they were added.
    fn note(&mut self, unit: &Unit, at: usize) -> Vec<usize> {
        if unit.shell != Shell::Posix {
            return Vec::new();
        }
        let key = unit.key();
        let found = self.find(unit.program.known(), key.as_deref());
        if let Some(program) = unit.program.known() {
            if !self.first_exact.contains_key(program) {
                self.first_exact.insert(program.to_string(), at);
            }
        }
        if let Some(key) = key {
            self.first_key.entry(key).or_insert(at);
        }
        found
    }

    /// The functions a unit that is already noted may call.
    fn calling(&self, unit: &Unit) -> Vec<usize> {
        if unit.shell != Shell::Posix {
            return Vec::new();
        }
        self.find(unit.program.known(), unit.key().as_deref())
    }

    /// The functions named `program`, or whose lower case name is `key`.
    fn find(&self, program: Option<&str>, key: Option<&str>) -> Vec<usize> {
        let mut found: Vec<usize> = program
            .and_then(|program| self.exact.get(program))
            .into_iter()
            .chain(key.and_then(|key| self.lower.get(key)))
            .flatten()
            .copied()
            .collect();
        found.sort_unstable();
        found.dedup();
        found
    }

    /// The first unit that may call the function `name`.
    fn first_call(&self, name: &str) -> Option<usize> {
        let by_name = self.first_exact.get(name).copied();
        let by_key = self.first_key.get(&name.to_ascii_lowercase()).copied();
        match (by_name, by_key) {
            (Some(one), Some(other)) => Some(one.min(other)),
            (one, other) => one.or(other),
        }
    }
}

/// The name rules know a program by.
///
/// On Windows a name is read by its last part after a drive's colon too: cmd
/// and PowerShell run `C:shutdown` from that drive's current folder, and an
/// elevated cmd starts in `C:\\Windows\\System32`. Windows drops the dots and
/// spaces that end a file's name, so `shutdown.exe.` is `shutdown`. A name
/// that is no more than a drive (PowerShell's `C:`) or dots (`.`) stays as
/// it is.
pub(crate) fn key(program: &str, shell: Shell) -> String {
    let mut base = program.rsplit(['/', '\\']).next().unwrap_or(program);
    if shell != Shell::Posix {
        if let [letter, b':', _, ..] = base.as_bytes() {
            if letter.is_ascii_alphabetic() {
                base = &base[2..];
            }
        }
        let trimmed = base.trim_end_matches(['.', ' ']);
        if !trimmed.is_empty() {
            base = trimmed;
        }
    }
    let lower = base.to_ascii_lowercase();
    // PowerShell runs a program's `.ps1` shim by its name (`npx.ps1`), as
    // the program: one it finds on the path, or names by a full path
    // (`C:\nodejs\npx.ps1`). A script named by a relative path
    // (`.\scripts\format.ps1`) is the project's own, and stays the script.
    let shim = !program.contains(['/', '\\']) || rooted(program);
    let extensions: &[&str] = if shell == Shell::PowerShell && shim {
        &[".exe", ".com", ".bat", ".cmd", ".ps1"]
    } else {
        &[".exe", ".com", ".bat", ".cmd"]
    };
    let stem = extensions
        .iter()
        .find_map(|extension| lower.strip_suffix(extension));
    match (shell, stem) {
        // Lower case on every shell: macOS's file system is case-insensitive
        // by default, so `/bin/RM` runs `rm`; a program literally named `RM`
        // on Linux is a negligible false positive.
        (Shell::Posix, None) => lower,
        (Shell::PowerShell, None) => crate::powershell::canonical(&lower).to_string(),
        (Shell::Cmd, None) => lower,
        (_, Some(stem)) => stem.to_string(),
    }
}

/// Whether the Windows path `path` starts at the root of a drive (`C:\x`,
/// `\x`, `\\server\share`), not at the folder the line is in.
fn rooted(path: &str) -> bool {
    match path.as_bytes() {
        [b'/' | b'\\', ..] => true,
        [letter, b':', b'/' | b'\\', ..] => letter.is_ascii_alphabetic(),
        _ => false,
    }
}

/// Whether `text`, a word as the shell expands it, is a wildcard pattern:
/// it holds a `*` or a `?`, or a `[` with a `]` after it (a `[` alone is a
/// name, as the program `[` is).
pub(crate) fn pattern(text: &str) -> bool {
    text.contains(['*', '?'])
        || text
            .split_once('[')
            .is_some_and(|(_, rest)| rest.contains(']'))
}

/// A write a redirect makes: `> file`, `>> file`.
#[derive(Debug, Clone)]
pub(crate) struct Write {
    pub(crate) shell: Shell,
    pub(crate) target: Arg,
    /// As [`Unit::dir`].
    pub(crate) dir: Option<Arg>,
    /// As [`Unit::hidden`].
    pub(crate) hidden: bool,
    /// Whether `dir` is one of the other folders the line may be in (see
    /// [`Unit::others`]), not where the walk has it: the write is judged
    /// from there, but a later run of a file the line wrote has its own
    /// reading of those folders, so it is not counted among the files
    /// written.
    pub(crate) also: bool,
}

impl Write {
    pub(crate) fn scope(&self) -> Scope<'_> {
        Scope {
            dir: self.dir.as_ref(),
            hidden: self.hidden,
        }
    }
}

/// One of the two options in [`Hidden`].
#[derive(Debug, Clone, Copy)]
pub(crate) enum Flag {
    Bash,
    Zsh,
}

/// The two options that let a wildcard match a leading dot: bash's (`shopt
/// -s dotglob`, `GLOBIGNORE`) and zsh's (`setopt globdots`). Each has its own
/// off switch, which is an error in the other shell and so clears only its
/// own; hidden names match when either is on.
///
/// zsh's `extendedglob` (see [`crate::extended`]) is kept with them: it
/// does not make a wildcard match a leading dot, but reaches as far and is
/// given back the same way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Hidden {
    bash: bool,
    zsh: bool,
    extended: bool,
}

impl Hidden {
    const ON: Self = Self {
        bash: true,
        zsh: true,
        extended: false,
    };

    fn any(self) -> bool {
        self.bash || self.zsh
    }

    /// Either shell's flag on in `self` or `other`.
    pub(crate) fn or(self, other: Self) -> Self {
        Self {
            bash: self.bash || other.bash,
            zsh: self.zsh || other.zsh,
            extended: self.extended || other.extended,
        }
    }
}

/// The folder a redirect opens its file from. A redirect on a `cd` is opened
/// before the `cd` runs, so from the folder the `cd` starts in, not the one
/// it goes to.
#[derive(Debug, Clone, Default)]
pub(crate) enum OpensFrom {
    /// Where the line is when the redirect is read.
    #[default]
    Line,
    /// The folder a unit starts in, with the others the line may be in then
    /// (see [`Start`]).
    Start(Box<Start>),
    /// The folder a unit starts in, with the others the line may be in then,
    /// and also where the line is when the redirect is read (where the unit
    /// goes): the folder the unit starts in is not certain, because its body
    /// runs more than once or an earlier `cd` may not have moved the line,
    /// so either may be the one.
    Both(Box<Start>),
    /// Any of these folders, and also where the line is when the redirect is
    /// read: a call to a function whose body moves the line starts in the
    /// folder the line is in when it is called, which is not known; the
    /// folders it was defined in are the ones the walk can name.
    Among(Vec<Option<Arg>>),
}

/// The folder a unit starts in, as [`OpensFrom`] names it. Kept behind a
/// box, so an [`OpensFrom`], which the walk holds at every level it
/// recurses through, stays small.
#[derive(Debug, Clone)]
pub(crate) struct Start {
    /// As [`Unit::dir`]; `None`: where the line began.
    dir: Option<Arg>,
    /// The other folders the line may be in then (as [`Unit::others`]).
    others: Vec<Option<Arg>>,
    /// Whether a `cd` that may not have run is among what left it there
    /// (see [`Split::unsure_writes`]).
    unsure: bool,
    /// For [`OpensFrom::Both`], where the unit went.
    went: Went,
}

/// Where a unit that [`OpensFrom::Both`] names went.
#[derive(Debug, Clone)]
enum Went {
    /// Where the line is when the redirect is read.
    Here,
    /// This folder (`None`: where the line began). It is not where the line
    /// is while what the unit's command expands is read from where it
    /// started (see [`Split::enter_start`]).
    To(Option<Arg>),
}

impl OpensFrom {
    fn start(dir: Option<Arg>, others: Vec<Option<Arg>>, unsure: bool) -> Self {
        Self::Start(Box::new(Start {
            dir,
            others,
            unsure,
            went: Went::Here,
        }))
    }

    fn both(dir: Option<Arg>, others: Vec<Option<Arg>>, went: Went) -> Self {
        Self::Both(Box::new(Start {
            dir,
            others,
            unsure: true,
            went,
        }))
    }
}

/// A redirect of a file onto the units of a statement: `cmd < f`, `cmd > f`.
#[derive(Debug, Clone)]
pub(crate) struct Redirect {
    /// The units it applies to, by index in [`Split::units`].
    pub(crate) units: Range<usize>,
    pub(crate) target: Arg,
    /// Whether it feeds the units' input (`<`), and not their output.
    pub(crate) input: bool,
    /// Whether the target is the text fed, a here-string or a
    /// here-document, and not a file.
    pub(crate) text: bool,
}

/// Units a command is handed the result of: what runs in its `$(…)` and
/// `<(…)`, in its here-document, in the value of an argument.
#[derive(Debug, Clone)]
pub(crate) struct Nested {
    /// The command's own units, by index in [`Split::units`].
    pub(crate) command: Range<usize>,
    /// The units that run for it.
    pub(crate) inside: Range<usize>,
}

/// A variable set from what a substitution prints: `k=$(cat f)`.
#[derive(Debug, Clone)]
pub(crate) struct Assigned {
    pub(crate) name: String,
    pub(crate) inside: Range<usize>,
    /// The variables the value names itself: `j=$k`, `j="$k-x"`.
    pub(crate) uses: Vec<String>,
}

/// The variables `text` names, as `$k`, `${k}` and `${k:-x}` do (`$key` is
/// not `k`).
pub(crate) fn referenced(text: &str) -> Vec<String> {
    text.split('$')
        .skip(1)
        .filter_map(|piece| {
            let piece = piece.strip_prefix('{').unwrap_or(piece);
            let end = piece
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(piece.len());
            piece.get(..end).filter(|name| !name.is_empty())
        })
        .map(str::to_string)
        .collect()
}

/// The variables PowerShell `text` names, in lower case as PowerShell
/// matches them, without a scope: `$k`, `${K}` and `$script:k` all name `k`
/// (`$env:k` names the environment, `env`).
pub(crate) fn referenced_powershell(text: &str) -> Vec<String> {
    const SCOPES: [&str; 5] = ["script", "global", "local", "private", "using"];
    text.split('$')
        .skip(1)
        .filter_map(|piece| {
            let piece = piece.strip_prefix('{').unwrap_or(piece);
            let name = |piece: &str| {
                let end = piece
                    .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .unwrap_or(piece.len());
                piece.get(..end).unwrap_or_default().to_ascii_lowercase()
            };
            let first = name(piece);
            let scoped = piece
                .get(first.len()..)
                .and_then(|rest| rest.strip_prefix(':'))
                .filter(|_| SCOPES.contains(&first.as_str()))
                .map(name);
            Some(scoped.unwrap_or(first)).filter(|name| !name.is_empty())
        })
        .collect()
}

/// The variables `text` names in `shell`: see [`referenced`] and
/// [`referenced_powershell`].
pub(crate) fn referenced_in(text: &str, shell: Shell) -> Vec<String> {
    match shell {
        Shell::PowerShell => referenced_powershell(text),
        Shell::Posix | Shell::Cmd => referenced(text),
    }
}

/// A function definition, noted where it begins (see [`Split::defining`]).
#[derive(Debug)]
pub(crate) struct Defining {
    name: String,
    /// Where the line is when the definition begins.
    dir: Option<Arg>,
    /// How many `cd`s this shell had run, as the walk counts them (a
    /// subshell gives them back), and how many units the walk had.
    moves: usize,
    first: usize,
    /// Whether where the line is then is not certain (see
    /// [`Split::opens_here`]).
    unsure: bool,
    /// Whether the definition has a redirect of a file named by a folder.
    opens: bool,
    /// Whether the definition surely runs in the line's own shell, and so
    /// takes the place of an earlier definition of the same name.
    replaces: bool,
    /// Where the definition's redirect opens its file from: at each call,
    /// from the folder the call is made in.
    pub(crate) here: OpensFrom,
}

/// A function that a call reaches from a folder the walk cannot always name:
/// its body moves the line, which the walk applies once, where the function
/// is defined; or its definition is redirected, which is opened at each call.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate fact about the function that the walk latches"
)]
struct Reaching {
    name: String,
    /// Where the line was when the definition began.
    dir: Option<Arg>,
    /// How many `cd`s the walk had read when the definition ended.
    moved: usize,
    /// Whether where the line was then is not certain.
    unsure: bool,
    /// Whether the body moves the line, or calls a function that does.
    moves: bool,
    /// Whether the definition has a redirect of a file named by a folder.
    opens: bool,
    /// How many units that may call it the walk has read.
    calls: usize,
    /// Whether it is called in a loop or a function body.
    looped: bool,
    /// Whether a finding has said so already.
    flagged: bool,
}

/// Whether terraform reads the variable `name` as arguments of its command:
/// `TF_CLI_ARGS`, and `TF_CLI_ARGS_<command>` for one command.
pub(crate) fn tf_cli_args(name: &str) -> bool {
    name == "TF_CLI_ARGS" || name.starts_with("TF_CLI_ARGS_")
}

/// Whether npm reads the variable `name` as its `call` setting, the command
/// `npx` and `npm exec` run in place of a program. npm reads the names of
/// its `npm_config_` variables in any case (`NPM_CONFIG_CALL`).
pub(crate) fn npm_call(name: &str) -> bool {
    name.eq_ignore_ascii_case("npm_config_call")
}

/// The variables whose value `psql` runs as a command line: the editor of
/// `\e`, the pager of a long result, and the shell of a bare `\!`.
pub(crate) const PSQL_PROGRAMS: [&str; 7] = [
    "EDITOR",
    "PSQL_EDITOR",
    "VISUAL",
    "PAGER",
    "PSQL_PAGER",
    "PSQL_WATCH_PAGER",
    "SHELL",
];

/// Whether a program reads the variable `name` as arguments or a command
/// line of its own: terraform's [`tf_cli_args`], npm's [`npm_call`], and the
/// editor, pager and shell `psql` runs ([`PSQL_PROGRAMS`]). The line's values
/// of these are noted where it sets them (see [`Split::argument_variables`]).
pub(crate) fn read_as_arguments(name: &str) -> bool {
    tf_cli_args(name) || npm_call(name) || PSQL_PROGRAMS.contains(&name)
}

/// The name a program reads, when `name` is one of [`read_as_arguments`]'s
/// written in any case, as Windows reads the names of variables
/// (`$env:tf_cli_args_APPLY` is `TF_CLI_ARGS_apply`, `$env:NPM_CONFIG_CALL`
/// is `npm_config_call`).
pub(crate) fn argument_variable(name: &str) -> Option<String> {
    if npm_call(name) {
        return Some("npm_config_call".to_string());
    }
    let upper = name.to_ascii_uppercase();
    if upper == "TF_CLI_ARGS" {
        return Some(upper);
    }
    let command = upper.strip_prefix("TF_CLI_ARGS_")?;
    Some(format!("TF_CLI_ARGS_{}", command.to_ascii_lowercase()))
}

/// Everything a line was split into.
#[derive(Debug, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate fact the one walk of the line latches"
)]
pub(crate) struct Split {
    pub(crate) units: Vec<Unit>,
    pub(crate) writes: Vec<Write>,
    /// The redirects' writes made where the line may be in more than one
    /// folder, because a `cd` before them may not have run (see
    /// [`Self::elsewhere`]): when it did not, the file is in a folder the walk
    /// may no longer have once a later `cd` moves the line on, so a later
    /// run of a script of its name, from any folder, may be it. Only that
    /// judgement reads these.
    pub(crate) unsure_writes: Vec<Write>,
    /// The redirects of files onto units, for the rules that follow a
    /// secret from a file to where it is sent.
    pub(crate) redirects: Vec<Redirect>,
    /// The text fed to units by a here-string or a here-document, as
    /// written: the statements a database client reads from its input.
    texts: Vec<Arg>,
    /// For each unit that is fed text, which of `texts` feed it, in order.
    fed: HashMap<usize, Vec<usize>>,
    /// What runs for a command inside its own arguments.
    pub(crate) nested: Vec<Nested>,
    /// The variables set from a substitution.
    pub(crate) assigned: Vec<Assigned>,
    /// The files redirected from (`< file`), where the line was.
    pub(crate) reads: Vec<Read>,
    /// The `for` loops over words written out, whose variable the body does
    /// not set: a rule reads the body with each word in place.
    pub(crate) bindings: Vec<Binding>,
    /// What splitting itself found: what could not be read, scripts known
    /// only when they run.
    pub(crate) findings: Vec<Finding>,
    /// For a unit that reads a file the code names without the guard knowing
    /// the whole path (`open(n + '/x')`), by its place in `units`: the
    /// finding that stands unless the unit finds a key in the part of the
    /// path that is known, as `read_secret` then says it more exactly.
    pub(crate) loose: HashMap<usize, Finding>,
    pipelines: usize,
    /// The stage of an outer pipeline that a pipeline runs in, when it runs
    /// in a stage of another: `(a | b) | c` runs `a | b` in the first stage.
    pub(crate) parents: HashMap<usize, Stage>,
    /// Where the `cd`s read so far moved to.
    dir: Option<Arg>,
    /// Whether `dir` is a place the line moved to that may hold code (see
    /// [`holds_code`]) or is only known when it runs, kept as the `cd`s are
    /// read so the folder's whole name is not read again after each one.
    dir_code: bool,
    /// Where the redirects being read open their files from (see
    /// [`OpensFrom`]).
    opens_from: OpensFrom,
    /// For each range of units [`Self::starts_in`] has read, the index of the
    /// unit in it that moves the line, if one does: a command with many
    /// redirects asks for its range once for each, and the answers must not
    /// read the command's units again, whatever runs in between.
    starts: HashMap<(usize, usize), Option<usize>>,
    /// The same for the folders of the functions a range of units calls that
    /// move the line (see [`Self::function_starts`]).
    called: HashMap<(usize, usize), Vec<Option<Arg>>>,
    /// Whether a `cd` read so far may not have moved the line: it sits in a
    /// branch, a loop, a function body, a pipeline stage or the background,
    /// or is the left side of `||`. Where the next `cd` starts is then not
    /// certain.
    maybe_moved: bool,
    /// The other folders the line may be in now, besides [`Self::dir`]:
    /// where it was before each `cd` that may not have run (in a branch,
    /// after `&&` or `||` or on the left of `||`, in a loop or a function
    /// body, in a pipeline stage or behind a wrapper, but not in an `if
    /// true` body), each moved on by every `cd` read since (a list of `&&`
    /// keeps the folders it may have stopped in until it ends, see
    /// [`Chain::stops`]). A later command's paths and redirects are judged
    /// from each of them as well (see [`Unit::others`]), and a run of a file
    /// the line wrote from each (see [`Unit::elsewhere`]): a file written
    /// before such a `cd` and run after it may be the one the line runs. At
    /// most [`MAX_ELSEWHERE`]; past that, one folder only known when it
    /// runs.
    elsewhere: Vec<Option<Arg>>,
    /// The folders the line is still in when a plain `cd` failed: one that
    /// is not in a branch, a loop, a function body, a pipeline stage or
    /// behind a wrapper (those are [`Self::elsewhere`]'s). A `cd` to a
    /// folder that is not there prints an error and the shell (POSIX, cmd,
    /// PowerShell) runs the next command where it was, so a later command's
    /// paths and redirects are judged from each of these as well (see
    /// [`Unit::others`]), and a file written before it and run after it may
    /// be the one the line runs (see [`Unit::stayed`]). Each is moved on by
    /// every `cd` read since; a command on the right side of `&&` after the
    /// `cd` runs only when it ran, so the list keeps them until it ends (see
    /// [`Chain::stayed`]). A `cd` that only steps up (`cd ..`) goes back
    /// through a folder the line came through and is taken as run. At most
    /// [`MAX_ELSEWHERE`]; past that, each file written so far is judged by
    /// its name (see [`Self::written_by_name`]), none are kept, and the line
    /// is [`Self::adrift`].
    stayed: Vec<Option<Arg>>,
    /// The shell of the last unit the walk added, whose spelling of a folder
    /// [`Self::distinct`] folds; `None` before the first.
    fold_shell: Option<Shell>,
    /// Whether the folders a plain `cd` that failed may have left the line
    /// in were once more than [`MAX_ELSEWHERE`]: from then on a later
    /// command's paths are also judged from a folder only known when it
    /// runs (see [`Unit::others`]), which stands for every folder such a
    /// `cd` may leave the line in, so none is kept (see [`Self::set_stayed`]).
    adrift: bool,
    /// How many of `writes`, and of `units`, have been judged by their name
    /// when the folders in [`Self::stayed`] were too many.
    named_writes: usize,
    named_units: usize,
    /// Whether the line may have turned on bash's `cdable_vars` or zsh's
    /// `cdablevars`: a `cd` to a name that is not a folder then goes to the
    /// folder the variable of that name holds, as one by `CDPATH` goes to
    /// a place only known when it runs (see [`by_cdpath`]).
    cdable: bool,
    /// The folders the last unit added to [`Self::stayed`], when it is a
    /// plain `cd`: the right side of `&&` after it runs only when it ran.
    last_stayed: Vec<Option<Arg>>,
    /// The folders PowerShell's `Push-Location` saved (see [`Locations`]).
    locations: Locations,
    /// How many times the line has saved or taken a folder of a location
    /// stack, or picked the stack: an action that runs later and does
    /// either leaves every stack unknown.
    location_steps: usize,
    /// The units that move the line from a folder that is not certain (see
    /// [`Self::maybe_moved`]; a loop or a function body runs again from where
    /// its last `cd` went), by their place in `units`.
    unsure_starts: HashSet<usize>,
    /// The units that move the line from a folder that may hold code (see
    /// [`Self::dir_code`]), by their place in `units`: what the shell expands
    /// for one before it runs is read from there (see [`Self::enter_start`]).
    code_starts: HashSet<usize>,
    /// For each [`Self::enter_start`] not yet put back, where the command it
    /// read from moved the line to; `None` for one that does not move it.
    aways: Vec<Option<Moved>>,
    /// In cmd, the drive the line is on, upper case: where it started, then
    /// where a drive switch, `cd /d` or `pushd` took it. `None` when it is
    /// on no drive or is only known when it runs.
    drive: Option<char>,
    /// Whether `drive` is only a guess: the move that put the line there
    /// (`cd /d`, `pushd`, `D:`) may not have run.
    drive_guess: bool,
    /// The drive the home directory is on.
    home_drive: Option<char>,
    /// Whether the line makes a PowerShell drive (`New-PSDrive`, `ndr`,
    /// `mount`) anywhere, before or after a `cd` in its text: a single letter
    /// in a `cd` may be one of another provider, not a disk.
    psdrive: bool,
    /// Variables the line sets, unsets or reads into (lower case): a path
    /// built from one of them is no longer the place its name says.
    reassigned: Vec<String>,
    /// Variables a `for` loop or a `read` sets (lower case): each holds one
    /// item of what the loop walks, so a rule that counts what a command
    /// reaches reads `"$c"` as every item, not one.
    looped: Vec<String>,
    /// What a POSIX line sets its variables to, for the places bash reads a
    /// value again as code (arithmetic, `${!x}`, `${x@P}`).
    pub(crate) values: crate::values::Values,
    /// The characters a backtick `u{…}` made in a PowerShell string that are
    /// a space that is not an ASCII one, a dash or a typographic quote: as a
    /// path or an argument each is the text it holds, but a script that holds
    /// one is not. Noted while a string is read, which only borrows the
    /// walker.
    splitting: RefCell<Vec<char>>,
    /// The PowerShell double-quoted strings whose expansions are only known
    /// when they run, by their source, with the text each holds where every
    /// expansion stands as `${}` (see [`Split::template`]). `None` for a
    /// string that holds a `$` or a backtick that is no expansion, which a
    /// reader of the text would take for one. Noted while a string is read,
    /// as `splitting` is.
    templates: RefCell<HashMap<String, Option<(String, bool)>>>,
    /// Whether the shell reading the line has turned on a option that lets a
    /// wildcard match a leading dot, bash's or zsh's. Once on it stays on,
    /// except that a subshell or a script in a process of its own gives it
    /// back as it was, and only a certain off switch turns it off.
    dotglob: Hidden,
    /// Whether the command being added hands the option to a shell it
    /// starts, and not to itself: `GLOBIGNORE=x bash -c '…'`. The shell that
    /// expands the command's own wildcards has run them before it applies.
    scoped_dotglob: bool,
    /// The values `NODE_OPTIONS` is given for the program being added: a
    /// prefix assignment, `env NODE_OPTIONS=…`, an `export` earlier in the
    /// line. Node reads them as its own options, and a script it starts gets
    /// them too.
    pub(crate) node_options: Vec<Arg>,
    /// The values `PYTHONPATH` is given for the program being added, noted
    /// as `node_options` is. Python puts each folder in it where an import
    /// looks, and runs its `sitecustomize` before any code it is given.
    pub(crate) python_path: Vec<Arg>,
    /// What `ZIPOPT` and `ZIP` hold for the program being added: `zip`
    /// reads them as options before its own. One value each, which an
    /// assignment replaces.
    pub(crate) zip_env: crate::zipopt::ZipEnv,
    /// The values the variables of [`read_as_arguments`] are given for the
    /// program being added, by name, noted as `node_options` is: terraform
    /// reads `TF_CLI_ARGS` and `TF_CLI_ARGS_<command>` as arguments of its
    /// command, npm reads `npm_config_call` as the command `npx` and `npm
    /// exec` run, and `psql` runs `PAGER`, `EDITOR` and the like as command
    /// lines. Each unit shares the list (see
    /// [`Split::note_argument_variable`]).
    pub(crate) argument_variables: Rc<Vec<(String, Arg)>>,
    /// How many assignments and wrappers hand the program being added an
    /// environment of its own (`FOO=1 python3 -c …`, `env`, `sudo`): the
    /// interpreter loads what that environment tells it to, which the code
    /// does not show.
    pub(crate) environment: usize,
    /// Whether an earlier part of the line assigned, read into or unset a
    /// variable on a line of its own (`NODE_OPTIONS=x; node -e …`): if the
    /// variable is already exported, which `PATH` and `HOME` always are, the
    /// assignment changes what the interpreter is given.
    pub(crate) assigned_earlier: bool,
    /// What inline code the guard found nothing in comes to when it is not
    /// read whole (see [`crate::inline`]): `unknown`, said once, and only
    /// when the line has no finding of its own, which already asks.
    pub(crate) unread: Vec<Finding>,
    /// The inline Python read whole that imports a module, with the folder
    /// it runs in: Python puts that folder first where an import looks, so
    /// outside the workspace (or where it is not known) a `json.py` there is
    /// what `import json` loads. Judged with the directories, where the
    /// line is judged.
    pub(crate) importing: Vec<Importing>,
    /// Whether the command being added has a word with zsh's `(D)` glob
    /// qualifier, which lets that command's wildcards match a leading dot
    /// without any option on: `rm -rf *git(D)`. It belongs to the command
    /// alone, so it is not part of [`Split::dotglob`].
    qualified: bool,
    /// How deep the line is inside something that may not run, or runs in
    /// a process of its own: the right side of `&&` and `||`, a branch, a
    /// loop, a function body, a background command.
    pub(crate) branches: usize,
    /// How many of [`Self::branches`] are an `if true; then …; fi` (see
    /// `Walker::always_taken`): it still counts as a branch for everything
    /// else, and is left out only for whether a `cd` in it may not have run.
    pub(crate) taken: usize,
    /// How many of [`Self::branches`] are the right side of `&&` or `||` in
    /// a list (see [`Self::link_start`]): a `cd` there is left out of
    /// whether it may not have run, which the list says for itself, once,
    /// when that side ends.
    links: usize,
    /// The list of commands joined by `&&` or `||` being read (see
    /// [`Chain`]).
    chain: Chain,
    /// Whether the next list read is the left side of the one being read
    /// (`a && b && c` is `(a && b) && c`), and so part of its chain.
    joins: bool,
    /// How deep the line is inside a function body or a loop, whose
    /// commands may run after the line has turned the option on.
    pub(crate) bodies: usize,
    /// The files `BASH_ENV` has been set to anywhere in the line, as a
    /// statement or after `export`, for each shell the line starts: wherever
    /// the shell sits, since a trap action, the next pass of a loop or a
    /// function body may run after the assignment.
    pub(crate) startup: Rc<Vec<Startup>>,
    /// Whether the line has set more `BASH_ENV` files than it reads.
    startup_over: bool,
    /// What the line does to `PWD` (see [`Pwd`]).
    pwd: Pwd,
    /// How deep the line is inside a loop or a function body, whose
    /// commands run again with other values.
    pub(crate) repeats: usize,
    /// How deep the line is inside a script handed to a shell whose input
    /// is a file or what a pipe gives (`type x.py | cmd /c python`, `cmd
    /// /c python < x.py`): what the script runs is handed that input.
    pub(crate) inherits_input: usize,
    /// Whether the line ever turned the option on, in this shell or in a
    /// script it ran, even if it turned it off again.
    ever_dotglob: bool,
    /// Whether the line ever turned zsh's `extendedglob` on, in this shell or
    /// in a script it ran, even if it turned it off again.
    ever_extended: bool,
    /// Whether the line is read a second time because it turns
    /// `extendedglob` on and has a function body or a loop, which may run
    /// after that: what they hold is read with it on (see [`split`]).
    extended_bodies: bool,
    /// Each function the line defines, by name, with the units of its body:
    /// a call runs them, handed the call's input.
    pub(crate) function_bodies: Vec<(String, Range<usize>)>,
    /// The functions the line defines, for a `GLOBIGNORE=x f` in front of a
    /// call.
    functions: Vec<String>,
    /// The units of each function body and alias the line defines, by name:
    /// what a call of the name runs (see [`Split::bodies_of`]).
    called_bodies: HashMap<String, Vec<Range<usize>>>,
    /// The names among [`Split::called_bodies`] an `alias` defines, whose
    /// call is its value followed by the call's words (see
    /// [`Split::is_alias`]).
    aliases: HashSet<String>,
    /// The functions whose body moves the line, or whose definition is
    /// redirected, which a call reaches from a folder the walk cannot always
    /// name.
    reaching: Vec<Reaching>,
    /// Where each of them is by name, and where each name is first called.
    names: Names,
    /// How many definitions of them have a body that moves the line.
    moving: usize,
    /// Whether a finding has said that the line defines more than
    /// [`MAX_MOVING_FUNCTIONS`] of them.
    moving_flagged: bool,
    /// How deep the line is inside a subshell, a substitution, a pipeline
    /// stage or a script in a process of its own, whose definitions of a
    /// function do not reach the rest of the line.
    pub(crate) apart: usize,
    /// The units and redirect writes added inside a function body or a loop.
    in_body: Vec<usize>,
    write_in_body: Vec<usize>,
    read_in_body: Vec<usize>,
    /// How many `cd`s this shell has run so far: a later one means an action
    /// that runs later may run from somewhere else. A subshell or a script
    /// in a process of its own gives the count back as it was, as it does
    /// the directory.
    moves: usize,
    /// How many `cd`s the walk has read in all, in a subshell or not, which
    /// nothing gives back: how an action that runs later tells it holds one.
    moved: usize,
    /// The actions that run later in this shell (a `trap`'s script).
    later: Vec<Later>,
    /// For each loop and function body the walk is reading, where it began
    /// (see [`Split::end_body`]).
    bodies_began: Vec<BodyStart>,
    /// Each function body read, with how many `cd`s the walk had read when
    /// it began: once the line is read, a body a `cd` came after runs from
    /// a folder only known when it runs (see [`Split::settle_bodies`]).
    function_runs: Vec<(Body, usize)>,
    /// The loops and function bodies that may run again from a folder only
    /// known when it runs (see [`Split::settle_bodies`]).
    reruns: Vec<Body>,
    /// Where the line was before each folder a wrapper started its program
    /// in (see [`Self::start_in`]), to put it back once that program is
    /// read.
    folders: Vec<Place>,
    /// How much nested script text has been read, in bytes (and one for
    /// each script), and how much of the line has been read again (see
    /// [`read_again`]): a line that makes the same script be read again and
    /// again must come back unreadable, not take forever.
    nested_read: usize,
    /// How much of the values of the variables a program reads as the
    /// command it runs (`npm_config_call`) has been read as scripts, in
    /// bytes, one for each (see [`read_from_variable`]).
    variable_read: usize,
    /// The bytes of text the grammars have parsed for the line, and the
    /// bytes their lexers were handed for it: see [`MAX_LEXED`].
    parsed: usize,
    lexed: usize,
    /// How many times the line has forked into two readings, each judged
    /// (see [`crate::launch::Launch::Either`]).
    forks: usize,
    /// How deep the line is inside `find … -exec find … -exec …`: each
    /// level is read once for every place the one outside it searches.
    pub(crate) find_depth: usize,
    /// How much work `find -exec` has been read to do, in all, counted in
    /// bytes built (each `{}` replaced by the place it stands for) and
    /// checked against `MAX_EXEC_WORK` in `find.rs`: the levels multiply, so
    /// a line must not make this grow without bound.
    pub(crate) find_work: usize,
    /// How many groups a `coproc` opened that the grammar did not see
    /// (`coproc { ls; }`, `coproc NAME { { ls; }; }`): it has no `coproc`,
    /// so it reads each `{` as a word and each `}` that closes one as a
    /// command of its own. The walk takes such a `}` off as it closes one,
    /// and runs nothing for it.
    pub(crate) coproc_groups: usize,
    /// What only `effect` needs of the line, kept only when it is read for
    /// `effect`, so `classify` costs what it did.
    pub(crate) kept: Kept,
    /// The aliases and functions a PowerShell line sets, which a command of
    /// that name may run (see [`crate::powershell::Aliases`]).
    pub(crate) powershell_aliases: crate::powershell::Aliases,
}

/// What the line does to `PWD`, read from the whole line.
#[derive(Debug, Default)]
struct Pwd {
    /// Whether a `cd` or `pushd` of the line, anywhere in it (a loop, a
    /// function, a trap action, a subshell), ever landed on a name that may
    /// hold code: `PWD` was that name for as long as the line stayed there.
    unplain: bool,
    /// Whether the line makes `PWD` the physical path, which resolves the
    /// links on the way: `cd -P`, `set -P`, `set -o physical`.
    physical: bool,
    /// Whether a POSIX `cd` of the line went to a target with a name after a
    /// `..` (`link/../etc`, `../x`): bash and zsh follow it physically when
    /// the folded folder does not exist, so the `..` the line's folder holds
    /// are not folded by spelling.
    climbed: bool,
    /// The first `PS4` or `BASH_ENV` value the line wrote with `$PWD` in it,
    /// to judge against every `cd` of the line once it is all read.
    used: Option<String>,
}

/// PowerShell's location stacks as the line leaves them: `Push-Location`
/// saves where the line is on a stack, and `Pop-Location` goes back to the
/// last folder saved there. Only a step the line is certain to take, in
/// order, is kept: one in a branch, a loop, a function body, the right side
/// of `&&` or `||`, an action that runs later or behind a wrapper may or may
/// not run, or run again, so after it every stack holds what is only known
/// when it runs. A stack the line did not fill held what the session had
/// before the line, which the line does not show.
#[derive(Debug, Clone, Default)]
pub(crate) struct Locations {
    /// Each stack the line saved a folder on, by name in lower case, with
    /// the folders saved, the last on top.
    stacks: Vec<(String, Vec<Saved>)>,
    /// The stack `Push-Location` and `Pop-Location` use when not given one,
    /// which `Set-Location -StackName` picks.
    default: Stack,
    /// Whether a step the line may or may not have taken came before: no
    /// stack can be read then.
    lost: bool,
}

/// The stack the location cmdlets use when not given one.
#[derive(Debug, Clone, Default)]
enum Stack {
    /// The session's own, named `default`.
    #[default]
    Session,
    /// One the line picked, by name in lower case.
    Named(String),
    /// One only known when it runs.
    Unknown,
}

/// Where the line was when `Push-Location` saved it, which a `Pop-Location`
/// goes back to.
#[derive(Debug, Clone)]
struct Saved {
    dir: Option<Arg>,
    dir_code: bool,
    elsewhere: Vec<Option<Arg>>,
    stayed: Vec<Option<Arg>>,
}

/// What a line holds that only [`crate::effect`] reads.
#[derive(Debug, Default)]
pub(crate) struct Kept {
    /// Whether the line is read for `effect`: nothing below is kept if not.
    pub(crate) on: bool,
    /// The variables the line sets or unsets, as written (`PATH`,
    /// `env:TEMP`): one can change which program runs or what it does.
    pub(crate) sets: Vec<String>,
    /// The variables of `for` loops that could be one of those: a loop's
    /// own variable is only a name for each of its words.
    pub(crate) loops: Vec<String>,
    /// Whether the line holds something that runs or changes without being
    /// a unit (a method call in PowerShell), or that cannot be told.
    pub(crate) opaque: bool,
    /// Whether a wrapper the line uses writes (`time -o FILE`).
    pub(crate) changes: bool,
}

/// A `for` variable and the words it takes, over the units of the body.
#[derive(Debug, Clone)]
pub(crate) struct Binding {
    pub(crate) variable: String,
    pub(crate) words: Vec<String>,
    /// The units added while the loop was read, by index in the split.
    pub(crate) units: Range<usize>,
    /// The redirects from a file added while it was read.
    pub(crate) reads: Range<usize>,
}

/// A read a redirect makes: `< file`.
#[derive(Debug, Clone)]
pub(crate) struct Read {
    pub(crate) shell: Shell,
    pub(crate) target: Arg,
    /// As [`Unit::dir`].
    pub(crate) dir: Option<Arg>,
    /// As [`Unit::hidden`].
    pub(crate) hidden: bool,
}

/// Inline Python read whole that imports a module (see
/// [`Split::importing`]).
#[derive(Debug, Clone)]
pub(crate) struct Importing {
    /// The folder the line had moved to when the code ran.
    pub(crate) dir: Option<Arg>,
    /// Whether the code sits in a function body or a loop, which runs again
    /// after any `cd` of the line.
    pub(crate) repeated: bool,
    /// What it comes to when that folder is not the workspace's.
    pub(crate) finding: Finding,
}

/// Where the walk was when an action that runs later began.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Began {
    units: usize,
    writes: usize,
    reads: usize,
    findings: usize,
    importing: usize,
    moved: usize,
    location_steps: usize,
}

impl Began {
    /// How many `cd`s the walk had read in all.
    pub(crate) fn moved(&self) -> usize {
        self.moved
    }
}

/// Where the walk was when a loop or a function body began: how much of
/// the line it had read, and how many `cd`s this shell had run, and the
/// walk had read.
#[derive(Debug)]
struct BodyStart {
    units: usize,
    writes: usize,
    reads: usize,
    moves: usize,
    moved: usize,
    /// Where the body's own redirects end and the ones written on a
    /// function's definition begin, once the walk is there.
    redirects: Option<(usize, usize)>,
}

/// What the walk added while it read a loop or a function body: its units
/// and its redirects' writes and reads.
#[derive(Debug)]
struct Body {
    units: Range<usize>,
    writes: Range<usize>,
    reads: Range<usize>,
}

/// Where a command moved the line to, set aside while what the shell
/// expands for it before it runs is read from where it started (see
/// [`Split::enter_start`]).
#[derive(Debug)]
struct Moved {
    /// The unit that moves the line, by its place in [`Split::units`].
    mover: usize,
    /// How many `cd`s this shell had run then (see [`Split::moves_so_far`]).
    moves: usize,
    dir: Option<Arg>,
    dir_code: bool,
    elsewhere: Vec<Option<Arg>>,
    stayed: Vec<Option<Arg>>,
    adrift: bool,
    last_stayed: Vec<Option<Arg>>,
}

/// Where the line was, to put back after a subshell or a nested script
/// whose `cd` must not reach the rest of the line.
#[derive(Debug, Clone)]
pub(crate) struct Place {
    dir: Option<Arg>,
    dir_code: bool,
    drive: Option<char>,
    drive_guess: bool,
    moves: usize,
    later: usize,
    maybe_moved: bool,
    elsewhere: Vec<Option<Arg>>,
    stayed: Vec<Option<Arg>>,
    locations: Locations,
}

/// Where the line is when the right side of an `||` ends the shell (see
/// [`Split::exits_after`]): the rest of the line runs only when the left side
/// did not fail.
#[derive(Debug)]
pub(crate) struct Exit {
    dir: Option<Arg>,
    dir_code: bool,
    drive: Option<char>,
    drive_guess: bool,
    maybe_moved: bool,
    elsewhere: Vec<Option<Arg>>,
    stayed: Vec<Option<Arg>>,
}

/// A list of commands joined by `&&` or `||` being read, from
/// [`Split::list_start`] to [`Split::list_end`].
#[derive(Debug)]
pub(crate) struct List {
    /// How many `cd`s this shell had run when the list began.
    moves: usize,
    /// Every folder the line may have been in when the list began.
    places: Vec<Option<Arg>>,
    /// The chain of the list this one is in, given back when this one ends;
    /// `None` when this list is the left side of the one being read, whose
    /// chain it is part of.
    outer: Option<Chain>,
}

/// The right side of `&&` or `||` in a list, from [`Split::link_start`] to
/// [`Split::link_end`].
#[derive(Debug)]
pub(crate) struct Link {
    /// How many `cd`s this shell had run when it began.
    moves: usize,
    /// Every folder the line may have been in when it began.
    places: Vec<Option<Arg>>,
    /// Whether the left side ends with a plain `cd` that may have failed
    /// (see [`Split::stayed`]): when this side does not run, that `cd`
    /// failed, and the line is where it stayed, not where it went.
    after_cd: bool,
}

/// What a list of commands joined by `&&` or `||` (its left sides that are
/// lists themselves included) leaves for the commands after it.
#[derive(Debug, Default)]
struct Chain {
    /// The folders the list may have stopped in: where the line was before
    /// each right side that moved it, which may not have run, and where the
    /// list began. A command later in the list runs only when the ones
    /// before it let it, so only a command after the list may be in one of
    /// them, until an `||` (see [`Self::or`]).
    stops: Vec<Option<Arg>>,
    /// The same for a plain `cd` that may have failed (see
    /// [`Split::stayed`]): the folders the line stayed in, kept from the
    /// right side of the `&&` after it, which runs only when it ran.
    stayed: Vec<Option<Arg>>,
    /// Whether the list has an `||`: a command after one runs when a side
    /// before it failed, or when the left of the `||` ran without the ones
    /// between, so from then on each folder the list may have stopped in is
    /// one the rest of it may run in too.
    or: bool,
}

/// An action that runs later, in this shell, from wherever the line has
/// moved to by then (a `trap`'s script, a PowerShell event's block): the
/// units and writes it added, and how many `cd`s the line had read when it
/// ended.
#[derive(Debug)]
struct Later {
    units: Range<usize>,
    writes: Range<usize>,
    reads: Range<usize>,
    importing: Range<usize>,
    /// The `cd`s this shell had run, and all the `cd`s read, when it ended.
    moves: usize,
    moved: usize,
    /// Whether a subshell copies it (`ERR`, `DEBUG`, `RETURN`): then it also
    /// runs from where a subshell moved to, so any `cd` counts.
    inherited: bool,
}

impl Later {
    /// Whether a `cd` has come since, given how many the shell has run and
    /// how many the walk has read.
    fn moved_since(&self, moves: usize, moved: usize) -> bool {
        if self.inherited {
            self.moved != moved
        } else {
            self.moves != moves
        }
    }
}

impl Split {
    /// Count one more fork of the line into two readings; `false` once
    /// `most` forks have been made, when the line is not read any further.
    pub(crate) fn fork(&mut self, most: usize) -> bool {
        self.forks += 1;
        self.forks <= most
    }

    /// The folder the `cd`s read so far moved the line to.
    pub(crate) fn directory(&self) -> Option<Arg> {
        self.dir.clone()
    }

    /// Whether the line makes the shell keep the physical path (`cd -P`,
    /// `set -P`), which follows a link before it applies a `..`.
    pub(crate) fn physical(&self) -> bool {
        self.pwd.physical
    }

    /// Whether `$PWD` is plain text here: the line has not moved, or moved to
    /// a name it wrote out that holds no code (`sub`). After a `cd` to one
    /// that may (`d$(rm -rf ~)`, `d\044(…)`, `"$x"`, a wildcard that matches
    /// a name the line made: `d*`) it is that name. So it is when the line
    /// makes `PWD` the physical path (`cd -P`, `set -P`: a link's target is
    /// the name) or sets `CDPATH` and moves (the folder it finds is the name).
    pub(crate) fn pwd_is_plain(&self) -> bool {
        !(self.pwd.physical || self.moves_by_cdpath() || self.dir_code)
    }

    /// Whether the line sets `CDPATH` and moves: the folder `cd` finds on it
    /// is the name `PWD` takes.
    fn moves_by_cdpath(&self) -> bool {
        self.moved > 0 && (self.cdable || self.reassigned("CDPATH"))
    }

    /// Note a `PS4` or `BASH_ENV` value written with `$PWD` in it, which the
    /// shell expands again where it runs, not where it is written.
    pub(crate) fn pwd_used(&mut self, value: &str) {
        if self.pwd.used.is_none() {
            self.pwd.used = Some(value.to_string());
        }
    }

    /// After the whole line is read: a value with `$PWD` in it is expanded
    /// where it runs, so it is judged against every `cd` of the line, those
    /// after it and those in loops, functions and trap actions as well, not
    /// only the ones before it.
    fn settle_pwd(&mut self) {
        if self.pwd.unplain || self.pwd.physical || self.moves_by_cdpath() {
            if let Some(value) = self.pwd.used.take() {
                self.problem(
                    Rule::Unknown,
                    "sets a variable the shell runs later to a value with the working directory in it, and the line moves to a folder whose name may hold code",
                    Some(&value),
                );
            }
        }
    }

    /// Note a `BASH_ENV` file the line sets, for each shell it starts after.
    pub(crate) fn add_startup(&mut self, entry: Startup) {
        if !startup::push(&mut self.startup, entry) {
            self.startup_overflow();
        }
    }

    /// The line sets more `BASH_ENV` files than are read: any shell it
    /// starts may run one of those left out.
    pub(crate) fn startup_overflow(&mut self) {
        if !self.startup_over {
            self.startup_over = true;
            self.problem(
                Rule::Unknown,
                "sets BASH_ENV to more files than the guard reads",
                None,
            );
        }
    }

    /// Note the value `value` the line gives the variable `name`, one of
    /// [`read_as_arguments`]'s. The list is copied only when a unit shares
    /// it, so a unit is handed the list without copying its values.
    pub(crate) fn note_argument_variable(&mut self, name: String, value: Arg) {
        Rc::make_mut(&mut self.argument_variables).push((name, value));
    }

    /// Keep the first `len` of [`Split::argument_variables`]: those noted
    /// after are the program's that was added.
    pub(crate) fn truncate_argument_variables(&mut self, len: usize) {
        if self.argument_variables.len() > len {
            Rc::make_mut(&mut self.argument_variables).truncate(len);
        }
    }

    /// Add a unit, run where the line has moved to; a `cd` moves the line.
    pub(crate) fn push(&mut self, mut unit: Unit) {
        self.fold_shell = Some(unit.shell);
        unit.dir.clone_from(&self.dir);
        unit.elsewhere.clone_from(&self.elsewhere);
        unit.stayed.clone_from(&self.stayed);
        unit.adrift = self.adrift;
        unit.argument_variables = Rc::clone(&self.argument_variables);
        self.last_stayed.clear();
        unit.hidden = self.hidden();
        unit.repeated = self.repeats > 0;
        self.note_call(&unit);
        if let Some(change) = unit
            .key()
            .filter(|_| unit.shell == Shell::Posix)
            .and_then(|key| dotglob::change(&key, &unit.args))
        {
            for (flag, on) in [(Flag::Bash, change.bash), (Flag::Zsh, change.zsh)] {
                // Behind `env` or `nohup` a builtin runs in a process of its
                // own, and behind zsh's `noglob` bash runs nothing.
                let certain = dotglob::in_shell(&unit.wrappers, flag) && unit.stage.is_none();
                match on {
                    Some(true) => self.set_flag(flag, true),
                    Some(false) => self.show(flag, certain),
                    None => {}
                }
            }
        }
        if let Some(on) = unit
            .key()
            .filter(|_| unit.shell == Shell::Posix)
            .and_then(|key| extended::change(&key, &unit.args))
        {
            if on {
                self.extend_glob();
            } else if dotglob::in_shell(&unit.wrappers, Flag::Zsh)
                && unit.stage.is_none()
                && self.branches == 0
            {
                self.dotglob.extended = false;
            }
        }
        if self.bodies > 0 {
            self.in_body.push(self.units.len());
        }
        if unit.shell == Shell::Posix && makes_physical(&unit) {
            self.pwd.physical = true;
        }
        if unit.shell == Shell::PowerShell && unit.key().as_deref() == Some("new-psdrive") {
            self.psdrive = true;
        }
        let mut moved = moves_to(&unit);
        // Whether this `cd` may not have run, so the line may still be where
        // it was.
        let mut unsure = false;
        if moved.is_some() {
            // A `cd` in a loop or a function body starts from where the
            // last pass left the line; one after a `cd` that may not have
            // moved it starts from a place that is not certain either.
            if self.repeats > 0 || self.maybe_moved {
                self.unsure_starts.insert(self.units.len());
            }
            // Whether this one moved the line is not certain when it may not
            // have run, or runs in a process of its own: a pipeline stage,
            // or behind a wrapper (`env cd`, `nohup cd`, `coproc { cd; }`,
            // `start cd`) that runs it as a program or in another shell.
            if self.branches > 0
                || self.repeats > 0
                || unit.stage.is_some()
                || !unit.wrappers.is_empty()
            {
                self.maybe_moved = true;
                // An `if true` body surely runs, so its `cd` does not leave
                // the line where it was; nor does a stage of a PowerShell
                // pipeline (each of its commands is one), which runs in the
                // line's own session.
                // The right side of `&&` or `||` is left to the list it is
                // in (see [`Self::link_end`]).
                unsure = self.branches > self.taken + self.links
                    || self.repeats > 0
                    || (unit.stage.is_some() && unit.shell != Shell::PowerShell)
                    || !unit.wrappers.is_empty();
            }
        }
        if unit.shell == Shell::Cmd {
            // A program only known when it runs may be a drive switch.
            if unit.program.is_unknown() {
                self.change_drive(None);
            }
            moved = moved.and_then(|target| self.cmd_target(&unit, target));
        }
        self.cdable |= unit.shell == Shell::Posix && cdable(&unit);
        if unit.shell == Shell::Posix && (self.cdable || self.reassigned("CDPATH")) {
            moved = moved.map(|target| by_cdpath(&unit, target));
        }
        // A `Pop-Location` the line is certain to run, of a folder the line
        // saved, goes back to it.
        let back = if unit.shell == Shell::PowerShell {
            self.location_step(&unit, moved.is_some())
        } else {
            None
        };
        if moved.is_some() && self.dir_code {
            self.code_starts.insert(self.units.len());
        }
        if let (Some(_), Some(saved)) = (&moved, back) {
            self.moves += 1;
            self.moved += 1;
            self.dir = saved.dir;
            self.dir_code = saved.dir_code;
            self.pwd.unplain |= self.dir_code;
            self.set_elsewhere(saved.elsewhere);
            self.set_stayed(saved.stayed);
        } else if let Some(target) = moved {
            self.move_line(&target, unit.shell, unsure);
        }
        self.units.push(unit);
    }

    /// Move the line by a `cd` to `target`, read as a `shell` path; `unsure`
    /// says the `cd` may not have run, so the line may still be where it was.
    fn move_line(&mut self, target: &Arg, shell: Shell, unsure: bool) {
        self.moves += 1;
        self.moved += 1;
        if shell == Shell::Posix && target.known().is_some_and(names_after_dots) {
            self.pwd.climbed = true;
        }
        let dir = self.moved_to(self.dir.as_ref(), target, shell);
        // Every other folder the line may be in moves too; a `cd` that
        // may not have run also leaves the line where it was.
        let mut elsewhere: Vec<Option<Arg>> = self
            .elsewhere
            .iter()
            .map(|from| Some(self.moved_to(from.as_ref(), target, shell)))
            .collect();
        if unsure {
            elsewhere.push(self.dir.clone());
            elsewhere.extend(self.elsewhere.iter().cloned());
        }
        // The folders a plain `cd` that failed left the line in move
        // on too; a `cd` that may not have run keeps them as they were,
        // and a plain one that may have failed keeps every folder the
        // line may be in now (see [`Self::stayed`]).
        let mut stayed: Vec<Option<Arg>> = self
            .stayed
            .iter()
            .map(|from| Some(self.moved_to(from.as_ref(), target, shell)))
            .collect();
        let mut added = Vec::new();
        if unsure {
            stayed.extend(self.stayed.iter().cloned());
        } else if !steps_up(target, shell) {
            added = std::iter::once(self.dir.clone())
                .chain(self.elsewhere.iter().cloned())
                .chain(self.stayed.iter().cloned())
                .filter(|folder| !stayed.contains(folder))
                .collect();
            stayed.extend(added.iter().cloned());
        }
        // The folder holds code when the target does (it replaced the
        // folder, or was put after it), or when the folder did and the
        // target was put after it: a join is longer than its target.
        // Only the target is read, never the whole folder again.
        let target_text = target.known();
        self.dir_code = match &dir {
            Arg::Known(text) => {
                target_text.is_none_or(holds_code)
                    || (self.dir_code && target_text != Some(text.as_str()))
            }
            _ => true,
        };
        self.pwd.unplain |= self.dir_code;
        self.dir = Some(dir);
        self.set_elsewhere(elsewhere);
        self.set_stayed(stayed);
        added.retain(|folder| self.stayed.contains(folder));
        self.last_stayed = added;
    }

    /// Keep PowerShell's location stacks (see [`Locations`]) for `unit`,
    /// which is about to be added: `Push-Location` saves where the line is,
    /// `Set-Location -StackName` picks the stack, and `Pop-Location` takes
    /// the last folder saved, which is returned when the line goes back to
    /// it. A step the line may or may not take, or take again, leaves every
    /// stack unknown, and so does a block or a script the guard does not read
    /// that may move the line (`moves`: `& $b`, `iex $s`), which may save or
    /// take a folder too.
    fn location_step(&mut self, unit: &Unit, moves: bool) -> Option<Saved> {
        if unit.relocates || (moves && unit.key().as_deref() == Some("invoke-expression")) {
            self.location_steps += 1;
            self.locations.lost = true;
            return None;
        }
        let key = unit.key()?;
        // An alias of a location cmdlet's name (`Set-Alias popd Get-Date`),
        // or of a name only known when it runs, may stand in for it.
        if renames_location(unit, &key) {
            self.lose_locations();
            return None;
        }
        if !matches!(
            key.as_str(),
            "push-location" | "pop-location" | "set-location"
        ) {
            return None;
        }
        let params = crate::powershell::Params::cmdlet(&unit.args, &crate::powershell::LOCATION);
        let named = params.has(&["stackname"]);
        // In a later stage of a pipeline it runs once for each item, which
        // may give it its folder and its stack (`$s | Pop-Location`).
        let piped = unit.stage.is_some_and(|stage| stage.index > 0);
        if key == "set-location" && !named && !piped {
            return None;
        }
        self.location_steps += 1;
        let certain = self.branches == self.taken
            && self.repeats == 0
            && self.bodies == 0
            && unit.wrappers.is_empty()
            && !piped
            && crate::powershell::location_binds(&unit.args, &key);
        if !certain {
            self.locations.lost = true;
            if key == "set-location" {
                self.locations.default = Stack::Unknown;
            }
            return None;
        }
        // The stack it names, in lower case; `None` when that is only known
        // when it runs (`-StackName $s`, or no value at all).
        let name = if named {
            match params.values(&["stackname"]).first() {
                Some(Arg::Known(name)) => Some(name.to_ascii_lowercase()),
                _ => None,
            }
        } else {
            match &self.locations.default {
                Stack::Session => Some("default".to_string()),
                Stack::Named(name) => Some(name.clone()),
                Stack::Unknown => None,
            }
        };
        match key.as_str() {
            "set-location" => {
                self.locations.default = name.map_or(Stack::Unknown, Stack::Named);
                None
            }
            "push-location" => {
                let Some(name) = name else {
                    self.locations.lost = true;
                    return None;
                };
                let saved = Saved {
                    dir: self.dir.clone(),
                    dir_code: self.dir_code,
                    elsewhere: self.elsewhere.clone(),
                    stayed: self.stayed.clone(),
                };
                match self.locations.stacks.iter_mut().find(|(n, _)| *n == name) {
                    Some((_, stack)) => stack.push(saved),
                    None => self.locations.stacks.push((name, vec![saved])),
                }
                None
            }
            _ => {
                let Some(name) = name else {
                    self.locations.lost = true;
                    return None;
                };
                if self.locations.lost {
                    return None;
                }
                let stack = self
                    .locations
                    .stacks
                    .iter_mut()
                    .find(|(n, _)| *n == name)
                    .map(|(_, stack)| stack);
                // A stack the line did not fill holds what the session saved
                // before it: from here on no stack can be read.
                let saved = stack.and_then(Vec::pop);
                if saved.is_none() {
                    self.locations.lost = true;
                }
                saved
            }
        }
    }

    /// Note that a step the line may or may not take came before, as a
    /// function or an alias that stands in for a location cmdlet does: no
    /// location stack can be read after it.
    pub(crate) fn lose_locations(&mut self) {
        self.location_steps += 1;
        self.locations.lost = true;
    }

    /// Start a runspace of its own (a thread job's, a `-Parallel` block's),
    /// whose location stacks are empty, and give back the line's, to put
    /// back with [`Self::restore_locations`] once it is read.
    pub(crate) fn take_locations(&mut self) -> Locations {
        std::mem::take(&mut self.locations)
    }

    /// Put back the line's location stacks, from [`Self::take_locations`].
    pub(crate) fn restore_locations(&mut self, locations: Locations) {
        self.locations = locations;
    }

    /// Where a `cd` to `target` takes the line from `from`.
    fn moved_to(&self, from: Option<&Arg>, target: &Arg, shell: Shell) -> Arg {
        match crate::path::within(from, target, shell) {
            // Once the line makes a drive, a drive letter may name it: the
            // place is only known when it runs.
            Arg::Known(text) if self.psdrive && crate::path::drive_of(&text).is_some() => {
                Arg::Unknown(text)
            }
            // A folder spelt longer, or deeper, than any a system opens:
            // every path read from it would cost its length. A `cd` folds
            // the `..` it applies, so such a spelling is folded (going down
            // and back up is no longer than staying), unless a `cd` may
            // have followed a link physically; still too long, the folder is
            // not followed.
            Arg::Known(text) if too_long(&text) => {
                let folded = (shell != Shell::Posix || !(self.pwd.physical || self.pwd.climbed))
                    .then(|| fold_dots(&text, shell))
                    .flatten()
                    .filter(|folded| !too_long(folded));
                match folded {
                    Some(folded) => Arg::Known(folded),
                    None => Arg::Unknown(target.text().to_string()),
                }
            }
            dir => dir,
        }
    }

    /// Say the line may also be in each of `folders` (see
    /// [`Self::elsewhere`]), once each and not where the walk has it; more
    /// than [`MAX_ELSEWHERE`] is one folder only known when it runs.
    fn set_elsewhere(&mut self, folders: Vec<Option<Arg>>) {
        let mut kept = self.distinct(folders);
        if kept.len() > MAX_ELSEWHERE {
            kept = vec![Some(Arg::Unknown(
                "where a cd that may not have run left the line".to_string(),
            ))];
        }
        self.elsewhere = kept;
    }

    /// Each of `folders` once, and not where the walk has the line: two
    /// spellings of a folder whose `..` fold to the same one are one folder,
    /// as a `cd` folds them (`a/..` is where `a` is), unless a `cd` may have
    /// followed a link physically (see [`Self::moved_to`]).
    fn distinct(&self, folders: Vec<Option<Arg>>) -> Vec<Option<Arg>> {
        let folds = self
            .fold_shell
            .filter(|shell| *shell != Shell::Posix || !(self.pwd.physical || self.pwd.climbed));
        let here = folder_key(self.dir.as_ref(), folds);
        let keys: Vec<_> = folders
            .iter()
            .map(|folder| folder_key(folder.as_ref(), folds))
            .collect();
        let mut keep = vec![false; keys.len()];
        for (at, folded) in keys.iter().enumerate() {
            let seen = keys
                .iter()
                .zip(&keep)
                .take(at)
                .any(|(earlier, kept)| *kept && earlier == folded);
            keep[at] = *folded != here && !seen;
        }
        folders
            .into_iter()
            .zip(keep)
            .filter_map(|(folder, kept)| kept.then_some(folder))
            .collect()
    }

    /// Say a plain `cd` that failed may have left the line in each of
    /// `folders` (see [`Self::stayed`]), once each and not where the walk has
    /// it; past [`MAX_ELSEWHERE`], the files written so far are judged by
    /// their name instead (see [`Self::written_by_name`]), and the line is
    /// [`Self::adrift`]. Once it is, it may be anywhere already: no folder is
    /// kept, and the files written since are judged by their name too.
    fn set_stayed(&mut self, folders: Vec<Option<Arg>>) {
        let mut kept = self.distinct(folders);
        if self.adrift || kept.len() > MAX_ELSEWHERE {
            self.written_by_name();
            self.adrift = true;
            kept.clear();
        }
        self.stayed = kept;
    }

    /// Past the most folders a plain `cd` that failed may have left the line
    /// in, the line may be in any of them: each file written so far counts
    /// as written in every folder by its name (see [`Self::unsure_writes`]),
    /// so a later run of a script of that name, from any folder, may be it,
    /// and a run of another name stays what it was.
    fn written_by_name(&mut self) {
        // A write placed from one of the other folders the line may be in
        // is not one of the files written (see [`Write::also`]).
        let redirects = self.writes.get(self.named_writes..).unwrap_or_default();
        let mut named: Vec<Write> = redirects
            .iter()
            .filter(|write| !write.also)
            .cloned()
            .collect();
        for unit in self.units.get(self.named_units..).unwrap_or_default() {
            named.extend(
                crate::detect::written_by(unit)
                    .into_iter()
                    .map(|target| Write {
                        shell: unit.shell,
                        target,
                        dir: unit.dir.clone(),
                        hidden: unit.hidden,
                        also: false,
                    }),
            );
        }
        self.named_writes = self.writes.len();
        self.named_units = self.units.len();
        self.unsure_writes.extend(named);
    }

    /// Where the cmd unit `unit`, which moves to `target`, takes the line,
    /// and `None` when it leaves the line where it was. `cd` and `chdir`
    /// without `/d` set the working directory of the drive they name and do
    /// not change the drive the line is on, so a path on another drive does
    /// not move the line; `/d`, `pushd` and a drive switch (`D:`) change the
    /// drive. A move to another drive may not have run (a branch, a failed
    /// `cd /d`), so the drive the line is then on is only a guess; when it is
    /// not known, or only guessed, and the path names another drive, the
    /// path may or may not have moved the line, so the place is not known
    /// either.
    fn cmd_target(&mut self, unit: &Unit, target: Arg) -> Option<Arg> {
        if let Some(letter) = cmd_drive_switch(unit) {
            self.change_drive(Some(letter.to_ascii_uppercase()));
            return Some(target);
        }
        let key = unit.key().unwrap_or_default();
        match key.as_str() {
            "popd" => {
                self.change_drive(None);
                return Some(target);
            }
            "cd" | "chdir" | "pushd" => {}
            // `cd..`, `cd\`: no drive in the name.
            _ => return Some(target),
        }
        let Some(text) = target.known() else {
            // A path only known when it runs may carry `/d`.
            self.change_drive(None);
            return Some(target);
        };
        // `/dD:\x` written together is read by cmd as `/d` and a path.
        let glued = unit.args.iter().filter_map(Arg::known).any(|arg| {
            arg.get(..2)
                .is_some_and(|start| start.eq_ignore_ascii_case("/d"))
                && arg.len() > 2
                && !is_switch(arg)
        });
        if glued {
            self.change_drive(None);
            return Some(Arg::Unknown(text.to_string()));
        }
        let switch = unit
            .args
            .first()
            .and_then(Arg::known)
            .is_some_and(|arg| arg.eq_ignore_ascii_case("/d"));
        // The drive a path names: its own letter, or home's for `~`.
        let named = if let Some(letter) = crate::path::drive_of(text) {
            Some(Some(letter))
        } else if text
            .strip_prefix('~')
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['\\', '/']))
        {
            Some(self.home_drive)
        } else {
            None
        };
        if switch || key == "pushd" {
            // A network path is mapped to a drive letter the line does not
            // name.
            if text.starts_with(r"\\") || text.starts_with("//") {
                self.change_drive(None);
            } else if let Some(there) = named {
                self.change_drive(there);
            }
            return Some(target);
        }
        match named {
            // Only the drive's own working directory is shown: nothing moves.
            Some(Some(_)) if text.len() == 2 => None,
            None => Some(target),
            Some(there) if there.is_some() && there == self.drive => Some(target),
            Some(_) if self.drive.is_some() && !self.drive_guess => None,
            Some(_) => Some(Arg::Unknown(text.to_string())),
        }
    }

    /// The line is now on `to` (`None`: not known). It is surely there only
    /// when it surely was, and the move did not change the drive.
    fn change_drive(&mut self, to: Option<char>) {
        self.drive_guess = !(to.is_some() && to == self.drive && !self.drive_guess);
        self.drive = to;
    }

    /// Note that `inside`, a run of units, ran for the command whose own units
    /// are `command`.
    pub(crate) fn nest(&mut self, command: Range<usize>, inside: Range<usize>) {
        if !inside.is_empty() && !command.is_empty() {
            self.nested.push(Nested { command, inside });
        }
    }

    /// Note that the file `target` is redirected onto `units`.
    pub(crate) fn redirect(&mut self, units: Range<usize>, target: Arg, input: bool) {
        self.redirects.push(Redirect {
            units,
            target,
            input,
            text: false,
        });
    }

    /// Note that the text `target` (a here-string, a here-document) is fed
    /// to `units`.
    pub(crate) fn feed(&mut self, units: Range<usize>, target: Arg) {
        self.redirects.push(Redirect {
            units,
            target,
            input: true,
            text: true,
        });
    }

    /// Note that the text `text`, a here-string or a here-document, is fed to
    /// `units`, as written.
    pub(crate) fn text_fed(&mut self, units: Range<usize>, text: Arg) {
        let index = self.texts.len();
        for unit in units {
            self.fed.entry(unit).or_default().push(index);
        }
        self.texts.push(text);
    }

    /// The text fed to the unit at `at` by a here-string or a here-document.
    pub(crate) fn fed_to(&self, at: usize) -> impl Iterator<Item = &Arg> {
        self.fed
            .get(&at)
            .into_iter()
            .flatten()
            .filter_map(|&index| self.texts.get(index))
    }

    /// Note that the variable `name` is set from what runs in `inside` and
    /// from the variables `value` names.
    pub(crate) fn assign(&mut self, name: &str, inside: Range<usize>, value: &str) {
        self.assign_uses(name, inside, referenced(value));
    }

    /// Note that the variable `name` is set from what runs in `inside` and
    /// from the variables `uses`, as [`Self::assign`] does, the names already
    /// read from the value (as PowerShell reads them, say).
    pub(crate) fn assign_uses(&mut self, name: &str, inside: Range<usize>, uses: Vec<String>) {
        if !inside.is_empty() || !uses.is_empty() {
            self.assigned.push(Assigned {
                name: name.to_string(),
                inside,
                uses,
            });
        }
    }

    /// The folders the functions called in `units` that move the line were
    /// defined in: a call opens its redirects before the body runs, from
    /// where the line is then, which the walk takes to be one of these. The
    /// walk applies the body's `cd` once, where the function is defined, so
    /// that is the folder the call starts in only when nothing has moved the
    /// line since (`moved_at` is how many `cd`s had been read when the
    /// redirected statement began), the function has not been called before,
    /// and the line was surely there when it was defined. When it is not
    /// certain, the call starts in a folder only known when it runs.
    fn function_starts(&mut self, units: Range<usize>, moved_at: usize) -> Vec<Option<Arg>> {
        if self.moving == 0 {
            return Vec::new();
        }
        // As for [`Self::starts_in`], a range is read once however many
        // redirects ask for it.
        let key = (units.start, units.end);
        if let Some(starts) = self.called.get(&key) {
            return starts.clone();
        }
        let mut starts = Vec::new();
        let mut unsure = Vec::new();
        let mut over = false;
        'units: for unit in self.units.get(units.clone()).into_iter().flatten() {
            for index in self.names.calling(unit) {
                let Some(function) = self.reaching.get(index).filter(|function| function.moves)
                else {
                    continue;
                };
                if !starts.contains(&function.dir) {
                    if starts.len() >= MAX_CALL_STARTS {
                        over = true;
                        break 'units;
                    }
                    starts.push(function.dir.clone());
                }
                let before = self
                    .names
                    .first_call(&function.name)
                    .is_some_and(|first| first < units.start);
                if function.unsure || before || function.moved != moved_at || self.repeats > 0 {
                    // The line may have been where it began when the
                    // definition was read.
                    if function.unsure && !starts.contains(&None) {
                        starts.push(None);
                    }
                    unsure.push(function.name.clone());
                }
            }
        }
        if over {
            self.problem(
                Rule::Unknown,
                "redirects calls to more functions that move the line, each from another folder, than it reads",
                None,
            );
        }
        self.problems_once(
            unsure,
            "redirects a call to a function that moves the line from a folder only known when it runs",
        );
        self.called.insert(key, starts.clone());
        starts
    }

    /// Where the redirects on a group, a loop or a branch whose body is
    /// `units` open their files from, before any of it runs: `start` (see
    /// [`Self::opens_here`]) when the body moves the line, `stays` when it
    /// does not (where the line is when the redirect is read, or, for the
    /// last command of a list, [`Self::opens_now`] before it), and the
    /// folder a function it calls was defined in when that moves the line.
    /// `moved_before` is how many `cd`s had been read when the statement
    /// began, and `moves_before` how many this shell had run: the body moves
    /// the line only if it ran one that a subshell did not give back.
    /// `by_folder` is as for [`Self::starts_in`]. When the body holds a `cd`
    /// that may not have run, the redirect still opens from where it started;
    /// a later run of a file it wrote is also judged from where the line
    /// began (see [`Self::elsewhere`]).
    pub(crate) fn opens_before(
        &mut self,
        start: OpensFrom,
        stays: OpensFrom,
        units: Range<usize>,
        moved_before: usize,
        moves_before: usize,
        by_folder: bool,
    ) -> OpensFrom {
        let moved = self.moves != moves_before;
        let mut dirs = if by_folder {
            self.function_starts(units, moved_before)
        } else {
            Vec::new()
        };
        if dirs.is_empty() {
            return if moved { start } else { stays };
        }
        if moved {
            match start {
                OpensFrom::Start(start) | OpensFrom::Both(start) => {
                    let Start { dir, others, .. } = *start;
                    dirs.push(dir);
                    dirs.extend(others);
                }
                OpensFrom::Among(more) => dirs.extend(more),
                OpensFrom::Line => {}
            }
        }
        OpensFrom::Among(dirs)
    }

    /// Where the redirects on `units` open their files from: the folder the
    /// first of them that moves the line (`cd`, `pushd`, `Set-Location`)
    /// starts in, as the shell opens them before it runs; where the line is
    /// when none of them moves it. `by_folder` says the redirect names a file
    /// by the folder it is opened from; one that does not (`2>&1`,
    /// `> /dev/null`) is not placed from the folder of a call to a function
    /// that moves the line.
    pub(crate) fn starts_in(&mut self, units: Range<usize>, by_folder: bool) -> OpensFrom {
        let key = (units.start, units.end);
        let mover = self.mover(units);
        let Some((index, unit)) =
            mover.and_then(|index| self.units.get(index).map(|unit| (index, unit)))
        else {
            let starts = if by_folder {
                self.function_starts(key.0..key.1, self.moved)
            } else {
                Vec::new()
            };
            if !starts.is_empty() {
                return OpensFrom::Among(starts);
            }
            // Where the first of them started, with the other folders the
            // line may have been in then: the last command of a list after
            // `&&` runs only when a plain `cd` before it did not fail, which
            // the line, once the list has ended, no longer says.
            return self.units.get(key.0).filter(|_| key.0 < key.1).map_or(
                OpensFrom::Line,
                |unit| {
                    OpensFrom::start(unit.dir.clone(), unit.others(), !unit.elsewhere.is_empty())
                },
            );
        };
        if self.unsure_starts.contains(&index) {
            // While what the command expands is read from where it started
            // (see [`Self::enter_start`]), where it went is set aside.
            let went = self
                .aways
                .iter()
                .rev()
                .flatten()
                .find(|moved| moved.mover == index)
                .map_or(Went::Here, |moved| Went::To(moved.dir.clone()));
            OpensFrom::both(unit.dir.clone(), unit.others(), went)
        } else {
            OpensFrom::start(unit.dir.clone(), unit.others(), false)
        }
    }

    /// The first of `units` that moves the line (`cd`, `pushd`,
    /// `Set-Location`), by its place in [`Self::units`]. The units are only
    /// added to, so a range holds the same units each time it is asked for:
    /// each range is read once, however often it is asked for.
    fn mover(&mut self, units: Range<usize>) -> Option<usize> {
        let key = (units.start, units.end);
        if let Some(mover) = self.starts.get(&key) {
            return *mover;
        }
        let start = units.start;
        let mover = self
            .units
            .get(units)
            .into_iter()
            .flatten()
            .position(|unit| moves_to(unit).is_some())
            .map(|index| start + index);
        self.starts.insert(key, mover);
        mover
    }

    /// Read what comes next from where the line was before the first of
    /// `units` that moves it, until [`Self::leave_start`]: the shell
    /// expands a command's words, redirects, here-documents and here-strings
    /// before the command runs, so what a substitution in them runs (`cd sub
    /// <<< "$(cat ../x)"`) starts where the `cd` does, not where it goes.
    /// When the `cd` starts from a folder that is not certain (a loop or a
    /// function body runs again from where its last pass went, see
    /// [`Self::unsure_starts`]), the line may also be where it went. When
    /// none of `units` moves the line, or `plain` says what is read holds
    /// nothing that runs (`cd sub`), nothing changes. Kept in the split, not
    /// in the walk's frame, which recurses once for each level of the parse
    /// tree.
    pub(crate) fn enter_start(&mut self, units: &Range<usize>, plain: bool) {
        if plain {
            self.aways.push(None);
            return;
        }
        let moved = self.mover(units.clone()).and_then(|mover| {
            let unit = self.units.get(mover)?;
            let (dir, mut elsewhere, stayed, adrift) = (
                unit.dir.clone(),
                unit.elsewhere.clone(),
                unit.stayed.clone(),
                unit.adrift,
            );
            if self.unsure_starts.contains(&mover) {
                elsewhere.extend(self.places());
            }
            // `$PWD` is plain text only when it is so in both folders.
            let code = self.dir_code || self.code_starts.contains(&mover);
            let moved = Moved {
                mover,
                moves: self.moves,
                dir: std::mem::replace(&mut self.dir, dir),
                dir_code: std::mem::replace(&mut self.dir_code, code),
                elsewhere: std::mem::take(&mut self.elsewhere),
                stayed: std::mem::replace(&mut self.stayed, stayed),
                adrift: std::mem::replace(&mut self.adrift, adrift),
                last_stayed: std::mem::take(&mut self.last_stayed),
            };
            self.set_elsewhere(elsewhere);
            Some(moved)
        });
        self.aways.push(moved);
    }

    /// Whether what was read since the last [`Self::enter_start`] moved the
    /// line itself, when that one read from where a command started: a
    /// PowerShell `$()` argument runs in the session (`cd $(cd ..; 'x')`). A
    /// `cd` in a subshell or a POSIX substitution has not moved it.
    pub(crate) fn moved_since_start(&self) -> bool {
        self.aways
            .last()
            .and_then(Option::as_ref)
            .is_some_and(|moved| moved.moves != self.moves)
    }

    /// Put the line back where the command the last [`Self::enter_start`]
    /// read from moved it to. When what was read in between moved the line
    /// itself (see [`Self::moved_since_start`]), the command moves it on from
    /// there, and may not have moved it at all.
    pub(crate) fn leave_start(&mut self) {
        if let Some(mover) = self.step_out() {
            self.move_on(mover);
        }
    }

    /// End the last [`Self::enter_start`] as [`Self::leave_start`] does,
    /// but when what was read in between moved the line itself, leave the
    /// line where that left it and give back the command that moves it on,
    /// for [`Self::move_on`] once the rest of what the command expands is
    /// read: a PowerShell command's later arguments run where an earlier
    /// `$()` left the session, before the command does.
    pub(crate) fn step_out(&mut self) -> Option<usize> {
        let moved_inside = self.moved_since_start();
        let moved = self.aways.pop().flatten()?;
        if moved_inside {
            return Some(moved.mover);
        }
        self.dir = moved.dir;
        self.dir_code = moved.dir_code;
        self.elsewhere = moved.elsewhere;
        self.stayed = moved.stayed;
        self.adrift = moved.adrift;
        self.last_stayed = moved.last_stayed;
        None
    }

    /// Where `mover`, a unit that moves the line, moves it to from where
    /// the line is now, as a path of its shell.
    fn moved_on_to(&self, mover: usize) -> Option<(Arg, Shell)> {
        let unit = self.units.get(mover)?;
        let target = moves_to(unit)?;
        // Where a `Pop-Location` goes back to was taken from its stack
        // where it was first read.
        let popped = unit.key().as_deref() == Some("pop-location");
        Some((
            if popped {
                Arg::Unknown(unit.program.text().to_string())
            } else {
                target
            },
            unit.shell,
        ))
    }

    /// Move the line on from where it is by `mover`, which
    /// [`Self::step_out`] gave back; it may fail and leave the line there.
    pub(crate) fn move_on(&mut self, mover: usize) {
        if let Some((target, shell)) = self.moved_on_to(mover) {
            self.move_line(&target, shell, true);
        }
    }

    /// Where a redirect read before [`Self::move_on`] opens its file from:
    /// where the line is, and where `mover` will move it on to from there.
    pub(crate) fn opens_moved_on(&self, mover: usize) -> OpensFrom {
        let Some((target, shell)) = self.moved_on_to(mover) else {
            return OpensFrom::Line;
        };
        let went = self.moved_to(self.dir.as_ref(), &target, shell);
        let mut others: Vec<Option<Arg>> = self
            .elsewhere
            .iter()
            .chain(&self.stayed)
            .map(|from| Some(self.moved_to(from.as_ref(), &target, shell)))
            .collect();
        others.extend(self.others());
        OpensFrom::both(Some(went), others, Went::Here)
    }

    /// The other folders the line may be in now, besides where the walk has
    /// it, as [`Unit::others`] says them for a unit added now.
    fn others(&self) -> Vec<Option<Arg>> {
        others(
            self.dir.as_ref(),
            &self.elsewhere,
            &self.stayed,
            self.adrift,
        )
    }

    /// Every folder the line may be in now: where the walk has it, then the
    /// others (see [`Self::elsewhere`]).
    fn places(&self) -> Vec<Option<Arg>> {
        std::iter::once(self.dir.clone())
            .chain(self.elsewhere.iter().cloned())
            .collect()
    }

    /// Begin a list of commands joined by `&&` or `||`; [`Self::list_end`]
    /// ends it. When [`Self::list_head`] said it is the left side of the
    /// list being read, it is part of that one's chain.
    pub(crate) fn list_start(&mut self) -> List {
        let outer = if std::mem::take(&mut self.joins) {
            None
        } else {
            Some(std::mem::take(&mut self.chain))
        };
        List {
            moves: self.moves,
            places: self.places(),
            outer,
        }
    }

    /// Say whether the next list read, the left side of the one being read,
    /// is a list itself (`a && b && c` is `(a && b) && c`): it is then part
    /// of the same chain, whose commands it runs first.
    pub(crate) fn list_head(&mut self, head: bool) {
        self.joins = head;
    }

    /// End `list`: the line may now be in any folder the list may have
    /// stopped in (see [`Chain::stops`]), unless the list is the left side
    /// of another, which says so when it ends.
    pub(crate) fn list_end(&mut self, list: List) {
        if let Some(outer) = list.outer {
            self.add_stops();
            self.chain = outer;
        }
    }

    /// An `||` in `list`: its right side runs only when the left failed, so
    /// a `cd` on the left may not have moved the line, and the line may be
    /// where the list began or in any folder it may have stopped in. A plain
    /// `cd` just before it that failed is when it runs (see
    /// [`Self::stayed`]).
    pub(crate) fn list_or(&mut self, list: &List) {
        self.last_stayed.clear();
        self.chain.or = true;
        if self.moves != list.moves {
            self.maybe_moved = true;
            self.chain.stops.extend(list.places.iter().cloned());
        }
        self.add_stops();
    }

    /// The right side of the `||` about to be read ends the shell (`cd s ||
    /// exit`): the rest of the line runs only when the left side did not
    /// fail, so a plain `cd` that ends it ran (none of the folders it may
    /// have stayed in, see [`Self::stayed`]), and so did every right side of
    /// `&&` in it (none of the folders it may have stopped in, see
    /// [`Chain`]). Note where the line is then, before [`Self::list_or`] says
    /// the left side may have failed, which only the right side reads;
    /// [`Self::exited`] puts it back when that side ends.
    pub(crate) fn exits_after(&self) -> Exit {
        let mut stayed = self.stayed.clone();
        stayed.retain(|folder| !self.last_stayed.contains(folder));
        Exit {
            dir: self.dir.clone(),
            dir_code: self.dir_code,
            drive: self.drive,
            drive_guess: self.drive_guess,
            maybe_moved: self.maybe_moved,
            elsewhere: self.elsewhere.clone(),
            stayed,
        }
    }

    /// The right side of `||` that ended the shell has been read: put the
    /// line back where [`Self::exits_after`] noted it, for what comes after.
    /// The `cd`s read since still count as read (see [`Self::moves`]), which
    /// only makes a later action less certain of where it runs.
    pub(crate) fn exited(&mut self, exit: Exit) {
        self.dir = exit.dir;
        self.dir_code = exit.dir_code;
        self.drive = exit.drive;
        self.drive_guess = exit.drive_guess;
        self.maybe_moved = exit.maybe_moved;
        self.elsewhere = exit.elsewhere;
        self.stayed = exit.stayed;
        self.last_stayed.clear();
        self.chain.stops.clear();
        self.chain.stayed.clear();
    }

    /// A statement the walk reads begins, or one that negates what it runs
    /// (`! cd s`, `-not (Set-Location s)`) ends: the right side of an `&&`
    /// after it runs when that statement succeeded, which says nothing of a
    /// plain `cd` before it (`cd s; [ -d b ] && rm -rf ../x`), so it is
    /// judged from the folders that `cd` may have stayed in too (see
    /// [`Self::link_start`]).
    pub(crate) fn statement(&mut self) {
        self.last_stayed.clear();
    }

    /// Begin a right side of `&&` or `||` in a list; [`Self::link_end`] ends
    /// it. It may not run, so it is a branch. After `&&` it runs only when
    /// the left side did, so the folders a plain `cd` that ends the left side
    /// stayed in when it failed are left for after the list (see
    /// [`Chain::stayed`]).
    pub(crate) fn link_start(&mut self) -> Link {
        let held = std::mem::take(&mut self.last_stayed);
        let after_cd = !held.is_empty();
        if after_cd {
            self.stayed.retain(|folder| !held.contains(folder));
            self.chain.stayed.extend(held);
        }
        self.branches += 1;
        self.links += 1;
        Link {
            moves: self.moves,
            places: self.places(),
            after_cd,
        }
    }

    /// End `link`, a right side of `list`: when it moved the line, it may
    /// not have run, so the list may have stopped where the line was before
    /// it, or where the list began, if the left side did not move it. After
    /// a plain `cd` that may have failed it does not run only when that `cd`
    /// failed, which leaves the line where it stayed ([`Chain::stayed`]), so
    /// not where the `cd` went: `cd a && cd ..` ends where it began. A
    /// command later in the list runs only when this side did, so these are
    /// left for after the list (see [`Chain::stops`]): a chain of `n` `cd`s
    /// leaves the line in at most `n + 1` folders.
    pub(crate) fn link_end(&mut self, list: &List, link: Link) {
        self.branches -= 1;
        self.links -= 1;
        if self.moves != link.moves {
            self.maybe_moved = true;
            if !link.after_cd {
                self.chain.stops.extend(link.places);
            }
            self.chain.stops.extend(list.places.iter().cloned());
            if self.chain.or {
                self.add_stops();
            }
        }
    }

    /// Say the line may be in any folder the list being read may have
    /// stopped in (see [`Chain::stops`]).
    fn add_stops(&mut self) {
        let stops = std::mem::take(&mut self.chain.stops);
        if !stops.is_empty() {
            let mut folders = std::mem::take(&mut self.elsewhere);
            folders.extend(stops);
            self.set_elsewhere(folders);
        }
        let stayed = std::mem::take(&mut self.chain.stayed);
        if !stayed.is_empty() {
            let mut folders = std::mem::take(&mut self.stayed);
            folders.extend(stayed);
            self.set_stayed(folders);
        }
    }

    /// How many `cd`s this shell has run so far, for
    /// [`Self::opens_before`]: a subshell
    /// gives the count back, as it does the directory, so a `cd` in one has
    /// not moved the line.
    pub(crate) fn moves_so_far(&self) -> usize {
        self.moves
    }

    /// How many `cd`s the walk has read, in a subshell or not, for
    /// [`Self::opens_before`].
    pub(crate) fn moved_so_far(&self) -> usize {
        self.moved
    }

    /// Whether any of `units` moves the line (`cd`, `pushd`, `Set-Location`).
    pub(crate) fn moves_in(&self, units: Range<usize>) -> bool {
        self.units
            .get(units)
            .into_iter()
            .flatten()
            .any(|unit| moves_to(unit).is_some())
    }

    /// Make the redirects read from now on open their files from `from`, and
    /// give back what it was, to put back.
    pub(crate) fn open_from(&mut self, from: OpensFrom) -> OpensFrom {
        std::mem::replace(&mut self.opens_from, from)
    }

    /// The folders a redirect read now opens its file from: one, or two when
    /// it is not certain where the unit it is on starts, each with whether
    /// it is one of the other folders the line may be in then (see
    /// [`Unit::others`]), after those.
    fn redirect_dirs(&self) -> Vec<(Option<Arg>, bool)> {
        let (dirs, also) = match &self.opens_from {
            OpensFrom::Line => (vec![self.dir.clone()], self.others()),
            OpensFrom::Start(start) => (vec![start.dir.clone()], start.others.clone()),
            OpensFrom::Both(start) => (
                vec![
                    start.dir.clone(),
                    match &start.went {
                        Went::Here => self.dir.clone(),
                        Went::To(dir) => dir.clone(),
                    },
                ],
                start.others.clone(),
            ),
            OpensFrom::Among(dirs) => (
                dirs.iter()
                    .cloned()
                    .chain(std::iter::once(self.dir.clone()))
                    .collect(),
                Vec::new(),
            ),
        };
        let mut placed: Vec<(Option<Arg>, bool)> =
            dirs.into_iter().map(|dir| (dir, false)).collect();
        for dir in also {
            if !placed.iter().any(|(known, _)| *known == dir) {
                placed.push((dir, true));
            }
        }
        placed
    }

    /// Where the line is now, with the other folders it may be in (see
    /// [`Unit::others`]): where a redirect on the last command of a list
    /// opens when that command does not move the line. The list itself may
    /// have stopped elsewhere, or a plain `cd` before `&&` failed, but then
    /// its last command does not run.
    pub(crate) fn opens_now(&self) -> OpensFrom {
        OpensFrom::start(self.dir.clone(), self.others(), !self.elsewhere.is_empty())
    }

    /// Where a redirect on a group, a loop or a branch that begins now opens
    /// its file from: the folder the line is in now. When the body then runs
    /// again from where its last pass left the line, or an earlier `cd` may
    /// not have moved the line, either may be the one, and the redirect is
    /// also placed from where the line is when it is read.
    pub(crate) fn opens_here(&self) -> OpensFrom {
        if self.maybe_moved {
            // The `cd` that may not have run could have left the line where
            // it began.
            OpensFrom::Among(vec![self.dir.clone(), None])
        } else if self.repeats > 0 {
            OpensFrom::both(self.dir.clone(), self.others(), Went::Here)
        } else {
            OpensFrom::start(self.dir.clone(), self.others(), false)
        }
    }

    /// Note that the definition of the function `name` begins; `opens` says
    /// its redirect names a file by a folder (see [`Self::defined`]).
    pub(crate) fn defining(&self, name: &str, opens: bool) -> Defining {
        Defining {
            name: name.to_string(),
            // Only a definition the line surely runs, in its own shell,
            // takes the place of an earlier one of the same name: not the
            // right side of `&&` or `||`, a branch, a loop, a function body,
            // the background, a subshell, a substitution, a pipeline stage
            // or a script in a process of its own.
            replaces: self.branches == 0 && self.repeats == 0 && self.apart == 0,
            dir: self.dir.clone(),
            moves: self.moves,
            first: self.units.len(),
            unsure: self.maybe_moved || self.repeats > 0,
            opens,
            here: self.opens_here(),
        }
    }

    /// Note that `units` are the body of the function or alias `name`: a
    /// call may run any body of its name the line defines. Past
    /// [`MAX_BODIES`] for one name, the two first are kept as one range from
    /// the start of the first to the end of the second, which holds both
    /// and whatever the line runs between them.
    pub(crate) fn body(&mut self, name: &str, units: Range<usize>) {
        if units.is_empty() {
            return;
        }
        let bodies = self.called_bodies.entry(name.to_string()).or_default();
        if bodies.len() >= MAX_BODIES {
            let first = bodies.remove(0);
            if let Some(second) = bodies.first_mut() {
                *second = first.start.min(second.start)..first.end.max(second.end);
            }
        }
        bodies.push(units);
    }

    /// Note that `units` are the value of `alias name=…`: a call of `name`
    /// runs it, with the call's words after its last command.
    pub(crate) fn alias_body(&mut self, name: &str, units: Range<usize>) {
        self.body(name, units);
        self.aliases.insert(name.to_string());
    }

    /// Whether an `alias` on the line defines `name`.
    pub(crate) fn is_alias(&self, name: &str) -> bool {
        self.aliases.contains(name)
    }

    /// The units of the bodies a unit that runs the program `name` may run:
    /// the functions and aliases of that name the line defines.
    pub(crate) fn bodies_of(&self, name: &str) -> &[Range<usize>] {
        self.called_bodies.get(name).map_or(&[], Vec::as_slice)
    }

    /// Note that the definition which began at `defining` has been read. A
    /// call to a function whose body moves the line, or that calls one that
    /// does, or whose definition is redirected, starts in a folder the walk
    /// has to work out from where the function was defined.
    pub(crate) fn defined(&mut self, defining: Defining) {
        self.function_bodies
            .push((defining.name.clone(), defining.first..self.units.len()));
        let Defining {
            name,
            dir,
            moves: moves_before,
            first,
            unsure,
            opens,
            replaces,
            ..
        } = defining;
        self.body(&name, first..self.units.len());
        // The walk moves its own line for every `cd` it reads, so a body
        // moves it as far as the walk is concerned unless a subshell or a
        // substitution gave the `cd` back. A `cd` in a pipeline stage, the
        // background or behind a wrapper may or may not reach the line; the
        // walk reads it as moving, and the call is placed from the folder
        // of the definition and from where the walk's line is.
        let moves = self.moves != moves_before
            || self.units.get(first..).into_iter().flatten().any(|unit| {
                self.names.calling(unit).into_iter().any(|index| {
                    self.reaching
                        .get(index)
                        .is_some_and(|function| function.moves)
                })
            });
        if (moves || opens) && self.reaching.len() >= MAX_MOVING_FUNCTIONS {
            // However the names are kept, a line that defines this many
            // (a name defined again counts again) is not worked out call by
            // call: it is not kept, and the line says so, once.
            if !self.moving_flagged {
                self.moving_flagged = true;
                self.problem(
                    Rule::Unknown,
                    "defines more functions that move the line or redirect their definition than it reads, so a call to one is placed from a folder only known when it runs",
                    None,
                );
            }
        } else if moves || opens {
            self.names.add(&name, self.reaching.len(), replaces);
            self.moving += usize::from(moves);
            self.reaching.push(Reaching {
                name,
                dir,
                moved: self.moved,
                unsure,
                moves,
                opens,
                calls: 0,
                looped: false,
                flagged: false,
            });
        }
    }

    /// Note a unit that may be a call to a function whose definition is
    /// redirected: the redirect is opened at each call, from the folder the
    /// call is made in, which is where the definition was read only when
    /// nothing has moved the line since, no earlier call moved it, and the
    /// line was surely there when it was defined.
    fn note_call(&mut self, unit: &Unit) {
        let (moved, repeats) = (self.moved, self.repeats);
        let mut unsure = Vec::new();
        let at = self.units.len();
        for index in self.names.note(unit, at) {
            let Some(function) = self.reaching.get_mut(index) else {
                continue;
            };
            if function.opens && !function.flagged {
                function.looped |= repeats > 0;
                let again = function.moves && (function.calls > 0 || repeats > 0);
                if function.unsure || function.moved != moved || again {
                    function.flagged = true;
                    unsure.push(function.name.clone());
                }
            }
            function.calls += 1;
        }
        self.problems_once(
            unsure,
            "calls a function whose redirect opens a file from a folder only known when it runs",
        );
    }

    /// Say `reason` of each of `names`, once for each name however many
    /// calls or definitions found it.
    fn problems_once(&mut self, names: Vec<String>, reason: &str) {
        let mut seen = HashSet::new();
        for name in names {
            if !seen.contains(&name) {
                self.problem(Rule::Unknown, reason, Some(&name));
                seen.insert(name);
            }
        }
    }

    /// After the whole line is read: a function whose redirected definition
    /// is called in a loop or a function body is called again after any `cd`
    /// that comes later in it.
    fn settle_functions(&mut self) {
        let moved = self.moved;
        let mut unsure = Vec::new();
        for function in &mut self.reaching {
            if function.opens && function.looped && !function.flagged && function.moved != moved {
                function.flagged = true;
                unsure.push(function.name.clone());
            }
        }
        self.problems_once(
            unsure,
            "calls a function whose redirect opens a file from a folder only known when it runs",
        );
    }

    /// Add a redirect's write, made where the line has moved to, or from
    /// where the unit it is on started (see [`Self::open_from`]).
    pub(crate) fn write(&mut self, shell: Shell, target: Arg) {
        let hidden = self.hidden();
        for (dir, also) in self.redirect_dirs() {
            if self.bodies > 0 {
                self.write_in_body.push(self.writes.len());
            }
            self.writes.push(Write {
                shell,
                target: target.clone(),
                dir,
                hidden,
                also,
            });
        }
        // Whether the line may be in more than one folder where the redirect
        // opens: a group's, loop's or branch's opens before its body runs,
        // and one from the folder a unit started in only when that was
        // certain.
        let unsure = match &self.opens_from {
            OpensFrom::Line => !self.elsewhere.is_empty(),
            OpensFrom::Start(start) => start.unsure,
            OpensFrom::Both(..) | OpensFrom::Among(_) => true,
        };
        if unsure {
            self.unsure_writes.push(Write {
                shell,
                target,
                dir: self.dir.clone(),
                hidden,
                also: false,
            });
        }
    }

    /// Record a `for` loop over `words` whose body, the units and the
    /// redirects from `start` on, does not set `variable`.
    pub(crate) fn bind(&mut self, variable: &str, words: Vec<String>, start: (usize, usize)) {
        self.bindings.push(Binding {
            variable: variable.to_string(),
            words,
            units: start.0..self.units.len(),
            reads: start.1..self.reads.len(),
        });
    }

    /// Add a redirect's read, made where the line has moved to, or from
    /// where the unit it is on started (see [`Self::open_from`]).
    pub(crate) fn read(&mut self, shell: Shell, target: Arg) {
        let hidden = self.hidden();
        for (dir, _) in self.redirect_dirs() {
            if self.bodies > 0 {
                self.read_in_body.push(self.reads.len());
            }
            self.reads.push(Read {
                shell,
                target: target.clone(),
                dir,
                hidden,
            });
        }
    }

    /// Whether a wildcard in what comes next may match a leading dot.
    pub(crate) fn hidden(&self) -> bool {
        self.dotglob.any() || self.qualified
    }

    /// Say the command being added has a word with a `(D)` glob qualifier,
    /// and say what it was, for the caller to put back after the command.
    ///
    /// A command that is read while another is being added (the words of
    /// `eval`, `watch` or `trap` turned into a script) keeps the outer one's
    /// qualifier: the shell expands the pattern, with the qualifier, before
    /// it hands what it matched on, so a script that is made of those names
    /// reads them as hidden ones too.
    pub(crate) fn qualify(&mut self, on: bool) -> bool {
        let before = self.qualified;
        self.qualified = on || before;
        before
    }

    /// Put back what [`Self::qualify`] said, once the command is added.
    pub(crate) fn restore_qualified(&mut self, before: bool) {
        self.qualified = before;
    }

    /// Whether the command being added hands the option to a shell it
    /// starts.
    pub(crate) fn scoped_hidden(&self) -> bool {
        self.scoped_dotglob
    }

    /// The options as the shell has them, to put back after a subshell or a
    /// script in a process of its own, whose change must not reach the rest
    /// of the line.
    pub(crate) fn hidden_snapshot(&self) -> Hidden {
        self.dotglob
    }

    pub(crate) fn restore_hidden(&mut self, hidden: Hidden) {
        self.dotglob = hidden;
    }

    fn set_flag(&mut self, flag: Flag, on: bool) {
        match flag {
            Flag::Bash => self.dotglob.bash = on,
            Flag::Zsh => self.dotglob.zsh = on,
        }
        self.ever_dotglob |= on;
    }

    /// Turn bash's option on for the rest of the shell: `GLOBIGNORE`,
    /// `BASHOPTS`.
    pub(crate) fn hide(&mut self) {
        self.set_flag(Flag::Bash, true);
    }

    /// Turn the option on for a script started with it, which is not this
    /// shell's own. The shell is not known, and a function body the line
    /// exports may run in it, so both flags go on.
    pub(crate) fn hide_for_script(&mut self) {
        self.dotglob = self.dotglob.or(Hidden::ON);
        self.ever_dotglob = true;
    }

    /// Turn zsh's `extendedglob` on for the rest of the shell, or for a
    /// script started with it (`zsh -o extendedglob -c '…'`).
    pub(crate) fn extend_glob(&mut self) {
        self.dotglob.extended = true;
        self.ever_extended = true;
    }

    /// Whether the words of what comes next are read as zsh reads them
    /// with `extendedglob` on: it is on, or the line turns it on somewhere
    /// and this is a function body or a loop, which may run after.
    pub(crate) fn extended_glob(&self) -> bool {
        self.dotglob.extended || (self.extended_bodies && self.bodies > 0)
    }

    /// Note that the line defines the function `name`.
    pub(crate) fn define_function(&mut self, name: &str) {
        self.functions.push(name.to_string());
    }

    /// Whether the line defines the function `name`.
    pub(crate) fn defines_function(&self, name: &str) -> bool {
        self.functions.iter().any(|known| known == name)
    }

    /// Whether a command read so far may change what a builtin's name
    /// stands for: an alias (`alias true=false`), or `enable` and `disable`
    /// (`enable -n true` turns the builtin off, so a program of that name
    /// from `PATH` runs).
    pub(crate) fn renames_builtins(&self) -> bool {
        self.units.iter().any(|unit| {
            unit.key()
                .is_some_and(|key| matches!(key.as_str(), "alias" | "enable" | "disable"))
        })
    }

    /// Say a function the line defines runs with the option on, as a
    /// `GLOBIGNORE=x f` in front of its call does.
    pub(crate) fn hide_functions(&mut self) {
        self.ever_dotglob = true;
    }

    /// Turn one option off, when the line is `certain` to run that in this
    /// shell: a pipeline stage runs in a subshell and a branch may not run,
    /// so neither can be counted on to. The other shell's option stays.
    pub(crate) fn show(&mut self, flag: Flag, certain: bool) {
        if certain && self.branches == 0 {
            match flag {
                Flag::Bash => self.dotglob.bash = false,
                Flag::Zsh => self.dotglob.zsh = false,
            }
        }
    }

    /// Say the command being added hands the option on when `on`, and say
    /// what it was, for [`Split::unscope_hidden`] to put back.
    pub(crate) fn scope_hidden(&mut self, on: bool) -> bool {
        let outer = self.scoped_dotglob;
        self.scoped_dotglob |= on;
        outer
    }

    pub(crate) fn unscope_hidden(&mut self, outer: bool) {
        self.scoped_dotglob = outer;
    }

    /// After the walk: a function body or a loop may run after the line has
    /// turned the option on, so when it ever did, what they hold is judged
    /// with it on.
    fn hide_bodies(&mut self) {
        if !self.ever_dotglob {
            return;
        }
        for &at in &self.in_body {
            if let Some(unit) = self.units.get_mut(at) {
                unit.hidden = true;
            }
        }
        for &at in &self.write_in_body {
            if let Some(write) = self.writes.get_mut(at) {
                write.hidden = true;
            }
        }
        for &at in &self.read_in_body {
            if let Some(read) = self.reads.get_mut(at) {
                read.hidden = true;
            }
        }
    }

    /// Note where an action that runs later begins, which the walk is about
    /// to read in place.
    pub(crate) fn begin_later(&self) -> Began {
        Began {
            units: self.units.len(),
            writes: self.writes.len(),
            reads: self.reads.len(),
            findings: self.findings.len(),
            importing: self.importing.len(),
            moved: self.moved,
            location_steps: self.location_steps,
        }
    }

    /// Note where a loop or a function body begins, which the walk is about
    /// to read in place (see [`Self::end_body`]). Kept off the frame of the
    /// walk, which the deepest nesting recurses through.
    #[inline(never)]
    pub(crate) fn begin_body(&mut self) {
        self.bodies_began.push(BodyStart {
            units: self.units.len(),
            writes: self.writes.len(),
            reads: self.reads.len(),
            moves: self.moves,
            moved: self.moved,
            redirects: None,
        });
    }

    /// Note that the redirects written on the definition of the function
    /// whose body was read last come next: each is opened where a call is
    /// made, which [`Self::defined`] works out, so they are not the body's.
    pub(crate) fn definition_redirects(&mut self) {
        let (writes, reads) = (self.writes.len(), self.reads.len());
        if let Some(start) = self.bodies_began.last_mut() {
            start.redirects.get_or_insert((writes, reads));
        }
    }

    /// Note that the loop or the function body begun last has been read in
    /// place. Each pass of a loop after the first starts where the last left
    /// the line, so after a `cd` this shell runs anywhere in the loop, each
    /// path of the loop is judged from a folder only known when it runs as
    /// well. A function body runs where it is called, after its definition,
    /// so the same holds for its paths when a `cd` is read anywhere from the
    /// start of the body on: in the body itself, which a second call starts
    /// from, or later in the line, a subshell's too, which may call it. It
    /// is the rule of an action that runs later, but each path is judged
    /// from where the walk has it too (see [`Self::settle_bodies`]).
    #[inline(never)]
    pub(crate) fn end_body(&mut self, function: bool) {
        let Some(start) = self.bodies_began.pop() else {
            return;
        };
        let (writes, reads) = start
            .redirects
            .unwrap_or((self.writes.len(), self.reads.len()));
        let body = Body {
            units: start.units..self.units.len(),
            writes: start.writes..writes,
            reads: start.reads..reads,
        };
        if function {
            self.function_runs.push((body, start.moved));
        } else if self.moves != start.moves {
            self.reruns.push(body);
        }
    }

    /// After the whole line is read, and the bodies' hidden names settled:
    /// each unit of a loop or a function body that may run again from a
    /// folder only known when it runs (see [`Self::end_body`]) is judged
    /// from there too (see [`Unit::rerun`]), and each of its redirects is
    /// made from there as well, once for each file. The bodies nest, so
    /// their ranges are joined first and each unit and redirect is read once.
    fn settle_bodies(&mut self) {
        for (body, moved) in std::mem::take(&mut self.function_runs) {
            if self.moved != moved {
                self.reruns.push(body);
            }
        }
        let reruns = std::mem::take(&mut self.reruns);
        let again = Some(Arg::Unknown(AGAIN.to_string()));
        for at in joined(reruns.iter().map(|body| body.units.clone())) {
            if let Some(unit) = self.units.get_mut(at) {
                unit.rerun = true;
            }
        }
        let mut seen = HashSet::new();
        let writes: Vec<Write> = joined(reruns.iter().map(|body| body.writes.clone()))
            .filter_map(|at| self.writes.get(at))
            .filter(|write| !same_folder(write.dir.as_ref(), again.as_ref()))
            .filter(|write| seen.insert((write.shell, write.target.clone(), write.hidden)))
            .map(|write| Write {
                dir: again.clone(),
                also: false,
                ..write.clone()
            })
            .collect();
        self.writes.extend(writes);
        seen.clear();
        let reads: Vec<Read> = joined(reruns.iter().map(|body| body.reads.clone()))
            .filter_map(|at| self.reads.get(at))
            .filter(|read| !same_folder(read.dir.as_ref(), again.as_ref()))
            .filter(|read| seen.insert((read.shell, read.target.clone(), read.hidden)))
            .map(|read| Read {
                dir: again.clone(),
                ..read.clone()
            })
            .collect();
        self.reads.extend(reads);
    }

    /// Note that the action which began at `began` has been read. It runs
    /// after the rest of the line, or between its commands, in this shell: if
    /// the line moves with a `cd` after it, where its relative paths land is
    /// not known, which [`Split::settle_later`] says once the line is read.
    /// A `cd` in the action itself may run before any of the line, so the
    /// rest of the line is read from somewhere unknown.
    pub(crate) fn end_later(&mut self, began: Began, inherited: bool) {
        if self.moved != began.moved {
            self.dir = Some(Arg::Unknown("where the action moves to".to_string()));
            self.dir_code = true;
        }
        // A location stack the action saves on or takes from is changed
        // whenever it runs.
        if self.location_steps != began.location_steps {
            self.locations.lost = true;
        }
        self.later.push(Later {
            units: began.units..self.units.len(),
            writes: began.writes..self.writes.len(),
            reads: began.reads..self.reads.len(),
            importing: began.importing..self.importing.len(),
            moves: self.moves,
            moved: self.moved,
            inherited,
        });
    }

    /// After the whole line is read: an action that runs later is read from
    /// where the line ends up, so when a `cd` came after it, its relative
    /// paths are known only when it runs.
    fn settle_later(&mut self) {
        for later in std::mem::take(&mut self.later) {
            if later.moved_since(self.moves, self.moved) {
                self.move_later(&later);
            }
        }
    }

    /// An action read from text with its expansions replaced by a
    /// placeholder shows `source`, as written, wherever the placeholder
    /// would be the name of what a finding is about.
    pub(crate) fn show_source(&mut self, began: Began, source: &str) {
        let shown = |arg: &mut Arg| {
            if arg.text().contains(crate::posix::OPAQUE) {
                *arg = Arg::Unknown(source.to_string());
            }
        };
        for unit in self.units.get_mut(began.units..).unwrap_or_default() {
            shown(&mut unit.program);
            unit.args.iter_mut().for_each(shown);
        }
        for write in self.writes.get_mut(began.writes..).unwrap_or_default() {
            shown(&mut write.target);
        }
        for read in self.reads.get_mut(began.reads..).unwrap_or_default() {
            shown(&mut read.target);
        }
        for finding in self.findings.get_mut(began.findings..).unwrap_or_default() {
            if finding
                .target
                .as_deref()
                .is_some_and(|target| target.contains(crate::posix::OPAQUE))
            {
                finding.target = Some(source.to_string());
            }
        }
    }

    /// Read everything added since `began` from somewhere only known when it
    /// runs.
    pub(crate) fn unplace(&mut self, began: Began) {
        self.move_later(&Later {
            units: began.units..self.units.len(),
            writes: began.writes..self.writes.len(),
            reads: began.reads..self.reads.len(),
            importing: began.importing..self.importing.len(),
            moves: self.moves,
            moved: self.moved,
            inherited: false,
        });
    }

    /// Start what is read next in `target`, as a process started there
    /// does (a PowerShell job's `-WorkingDirectory`): it is no `cd` of this
    /// shell, so the caller puts the line back where it was afterwards.
    pub(crate) fn enter(&mut self, target: &Arg, shell: Shell) {
        let dir = self.moved_to(self.dir.as_ref(), target, shell);
        let elsewhere = self
            .elsewhere
            .iter()
            .map(|from| Some(self.moved_to(from.as_ref(), target, shell)))
            .collect();
        let stayed = self
            .stayed
            .iter()
            .map(|from| Some(self.moved_to(from.as_ref(), target, shell)))
            .collect();
        let target_text = target.known();
        self.dir_code = match &dir {
            Arg::Known(text) => {
                target_text.is_none_or(holds_code)
                    || (self.dir_code && target_text != Some(text.as_str()))
            }
            _ => true,
        };
        self.dir = Some(dir);
        self.set_elsewhere(elsewhere);
        self.set_stayed(stayed);
    }

    /// Read an action that runs later from somewhere unknown.
    fn move_later(&mut self, later: &Later) {
        let moved = Arg::Unknown("where the line moves to".to_string());
        for unit in self.units.get_mut(later.units.clone()).unwrap_or_default() {
            unit.dir = Some(moved.clone());
        }
        for write in self
            .writes
            .get_mut(later.writes.clone())
            .unwrap_or_default()
        {
            write.dir = Some(moved.clone());
        }
        for read in self.reads.get_mut(later.reads.clone()).unwrap_or_default() {
            read.dir = Some(moved.clone());
        }
        for code in self
            .importing
            .get_mut(later.importing.clone())
            .unwrap_or_default()
        {
            code.dir = Some(moved.clone());
        }
    }

    /// Start what a wrapper runs in `target`, the folder its own option
    /// names (`env -C DIR`, `pnpm --dir DIR`, `Start-Process
    /// -WorkingDirectory DIR`, `start /d DIR`), read as a `shell` path: every
    /// folder the line may be in moves there, as for a `cd` that ran. The
    /// wrapper fails rather than run its program anywhere else. The move is
    /// that program's alone: [`Self::leave_folders`] puts the line back.
    pub(crate) fn start_in(&mut self, target: &Arg, shell: Shell) {
        self.folders.push(self.dir_snapshot());
        if shell == Shell::Cmd {
            // `start /d` names the whole folder: its drive too, and a network
            // path is on a drive the line does not name.
            match target.known() {
                Some(text) if text.starts_with(r"\\") || text.starts_with("//") => {
                    self.change_drive(None);
                }
                Some(text) => {
                    if let Some(letter) = crate::path::drive_of(text) {
                        self.change_drive(Some(letter));
                    }
                }
                None => self.change_drive(None),
            }
        }
        let dir = self.moved_to(self.dir.as_ref(), target, shell);
        let elsewhere: Vec<Option<Arg>> = self
            .elsewhere
            .iter()
            .map(|from| Some(self.moved_to(from.as_ref(), target, shell)))
            .collect();
        let stayed: Vec<Option<Arg>> = self
            .stayed
            .iter()
            .map(|from| Some(self.moved_to(from.as_ref(), target, shell)))
            .collect();
        // As for a `cd`: the folder holds code when the target does, or when
        // the folder did and the target was put after it.
        let target_text = target.known();
        self.dir_code = match &dir {
            Arg::Known(text) => {
                target_text.is_none_or(holds_code)
                    || (self.dir_code && target_text != Some(text.as_str()))
            }
            _ => true,
        };
        self.pwd.unplain |= self.dir_code;
        self.dir = Some(dir);
        self.set_elsewhere(elsewhere);
        self.set_stayed(stayed);
    }

    /// How many folders wrappers have started their programs in and the
    /// line is still in, to give to [`Self::leave_folders`].
    pub(crate) fn folders_mark(&self) -> usize {
        self.folders.len()
    }

    /// Put the line back where it was before the folders wrappers started
    /// their programs in since `mark` (see [`Self::start_in`]).
    pub(crate) fn leave_folders(&mut self, mark: usize) {
        if mark < self.folders.len() {
            let mut left = self.folders.split_off(mark);
            let place = left.swap_remove(0);
            self.restore_dir(place);
        }
    }

    /// Run what comes next from a folder only known when it runs, `why`, as
    /// a `cd` there would: the script a program runs in a folder of its own
    /// choosing (`git submodule foreach`). Put back with
    /// [`Self::restore_dir`] from a [`Self::dir_snapshot`] taken before.
    pub(crate) fn move_unknown(&mut self, why: &str) {
        self.moves += 1;
        self.moved += 1;
        self.dir = Some(Arg::Unknown(why.to_string()));
        self.dir_code = true;
        self.pwd.unplain = true;
        self.elsewhere.clear();
        self.stayed.clear();
        self.last_stayed.clear();
    }

    /// Where the line has moved to, to put back after a subshell or a nested
    /// script whose `cd` must not reach the rest of the line.
    pub(crate) fn dir_snapshot(&self) -> Place {
        Place {
            dir: self.dir.clone(),
            dir_code: self.dir_code,
            drive: self.drive,
            drive_guess: self.drive_guess,
            moves: self.moves,
            later: self.later.len(),
            maybe_moved: self.maybe_moved,
            elsewhere: self.elsewhere.clone(),
            stayed: self.stayed.clone(),
            locations: self.locations.clone(),
        }
    }

    /// Put the line back where it was. An action that runs later, set inside
    /// what ended, is settled by the `cd`s inside it, and the rest of the
    /// line counts against it as it would against one set before.
    pub(crate) fn restore_dir(&mut self, place: Place) {
        let inside = self.later.split_off(place.later);
        for mut later in inside {
            if later.moved_since(self.moves, self.moved) {
                self.move_later(&later);
            } else {
                later.moves = place.moves;
                self.later.push(later);
            }
        }
        self.dir = place.dir;
        self.dir_code = place.dir_code;
        self.drive = place.drive;
        self.drive_guess = place.drive_guess;
        self.moves = place.moves;
        self.maybe_moved = place.maybe_moved;
        self.elsewhere = place.elsewhere;
        self.stayed = place.stayed;
        self.locations = place.locations;
        self.last_stayed.clear();
    }

    /// Record that the line sets or unsets the variable `name`, for `effect`.
    pub(crate) fn set(&mut self, name: &str) {
        if self.kept.on {
            self.kept.sets.push(name.to_string());
        }
    }

    /// Record the variable of a `for` loop, for `effect`.
    pub(crate) fn kept_loop(&mut self, name: &str) {
        if self.kept.on {
            self.kept.loops.push(name.to_string());
        }
    }

    /// Record that the line runs or changes something that is not a unit,
    /// for `effect`.
    pub(crate) fn opaque(&mut self) {
        self.kept.opaque |= self.kept.on;
    }

    /// Record what a wrapper's own options do, for `effect`.
    pub(crate) fn wrapped(&mut self, effect: Kind) {
        match effect {
            Kind::Reads => {}
            Kind::Changes => self.kept.changes |= self.kept.on,
            Kind::Unknown => self.opaque(),
        }
    }

    /// Record that the line sets the variable `name`.
    pub(crate) fn reassign(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        if !self.reassigned.contains(&name) {
            self.reassigned.push(name);
        }
    }

    /// Record that a loop or a `read` sets the variable `name`.
    pub(crate) fn loop_variable(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        if !self.looped.contains(&name) {
            self.looped.push(name);
        }
    }

    /// Whether a loop or a `read` in the line sets the variable `name`.
    pub(crate) fn looped(&self, name: &str) -> bool {
        self.looped
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
    }

    /// Whether the line sets the variable `name` anywhere.
    pub(crate) fn reassigned(&self, name: &str) -> bool {
        self.reassigned
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
    }

    /// Note the characters a backtick `u{…}` made in a PowerShell string that
    /// PowerShell reads as more than a character when the text runs as code.
    pub(crate) fn note_splitting(&self, made: &[char]) {
        let mut splitting = self.splitting.borrow_mut();
        for c in made {
            if !splitting.contains(c) {
                splitting.push(*c);
            }
        }
    }

    /// Note the text the PowerShell double-quoted string `source` holds, its
    /// expansions standing as `${}`, and whether one of them runs a command
    /// (`$(…)`), or `None` when it cannot be read so.
    pub(crate) fn note_template(&self, source: &str, text: Option<(String, bool)>) {
        self.templates
            .borrow_mut()
            .entry(source.to_string())
            .or_insert(text);
    }

    /// The PowerShell double-quoted string `source`, whose expansions are only
    /// known when it runs, as a template: the text it holds with each
    /// expansion standing as `${}`, which a reader of a database statement
    /// reads as it reads a POSIX shell's (an expansion is a value, and where
    /// a statement starts, a statement only known when it runs). `None` when
    /// `source` is no such string.
    pub(crate) fn template(&self, source: &str) -> Option<Arg> {
        let (text, runs) = self.templates.borrow().get(source).cloned().flatten()?;
        Some(Arg::Template {
            text,
            source: source.into(),
            runs,
        })
    }

    /// Whether `script` holds a character noted by [`Split::note_splitting`]:
    /// run as code, its words are not the ones the guard's reading of the
    /// text finds. The script need not be a whole noted string: one reached
    /// through `cmd /c` or `bash -c` is only part of the string that holds it.
    fn splits_script(&self, script: &str) -> bool {
        let splitting = self.splitting.borrow();
        !splitting.is_empty() && script.chars().any(|c| splitting.contains(&c))
    }

    /// A new pipeline's number; `parent` is the stage of another pipeline it
    /// runs in.
    pub(crate) fn pipeline(&mut self, parent: Option<Stage>) -> usize {
        self.pipelines += 1;
        if let Some(parent) = parent {
            self.parents.insert(self.pipelines, parent);
        }
        self.pipelines
    }

    /// Whether the environment of a program started now may differ from the
    /// one the line shows: an assignment or a wrapper hands it one, or an
    /// earlier unit exported a variable, turned them all on (`set -a`) or
    /// read a file that may set them.
    #[cfg_attr(
        not(feature = "inline"),
        allow(dead_code, reason = "only the reader of inline code asks")
    )]
    pub(crate) fn environment_set(&self) -> bool {
        self.environment > 0
            || self.assigned_earlier
            || self.units.iter().any(|unit| {
                unit.key().is_some_and(|key| {
                    matches!(
                        key.as_str(),
                        "export"
                            | "declare"
                            | "typeset"
                            | "readonly"
                            | "local"
                            | "set"
                            | "source"
                            | "."
                            | "read"
                            | "let"
                            | "mapfile"
                            | "readarray"
                            | "getopts"
                            // They change what a program's name stands for:
                            // an alias, a path `hash` remembers, a builtin
                            // `enable` loads or turns off.
                            | "alias"
                            | "unalias"
                            | "hash"
                            | "enable"
                    ) || (key == "printf"
                        && unit
                            .args
                            .iter()
                            .filter_map(Arg::known)
                            .any(|arg| arg.strip_prefix("-v").is_some()))
                })
            })
    }

    /// Note that code is given to an interpreter that the guard does not read
    /// whole: the line is `unknown` unless it has a finding of its own.
    pub(crate) fn unread_code(&mut self, code: &str) {
        if self.unread.is_empty() {
            self.unread.push(Self::unread_finding(code));
        }
    }

    /// What inline code the guard does not read whole comes to.
    pub(crate) fn unread_finding(code: &str) -> Finding {
        Finding {
            rule: Rule::Unknown,
            reason: "runs code the guard does not read fully".to_string(),
            target: Some(crate::inline::shorten(code)),
        }
    }

    /// Note inline Python read whole that imports a module, run from the
    /// folder the line has moved to (see [`Split::importing`]).
    #[cfg_attr(
        not(feature = "inline"),
        allow(dead_code, reason = "only the reader of inline code notes an import")
    )]
    pub(crate) fn imports(&mut self, code: &str) {
        self.importing.push(Importing {
            dir: self.dir.clone(),
            repeated: self.repeats > 0,
            finding: Self::unread_finding(code),
        });
    }

    /// Whether the line moves to another folder anywhere: `cd`, `pushd`,
    /// `popd`.
    pub(crate) fn ever_moves(&self) -> bool {
        self.moved > 0
    }

    pub(crate) fn problem(&mut self, rule: Rule, reason: &str, target: Option<&str>) {
        self.findings.push(Finding {
            rule,
            reason: reason.to_string(),
            target: target.map(str::to_string),
        });
    }
}

/// Whether a name may hold code or stand for other names once the shell has
/// it as the working directory: `$(…)`, a backtick, a backslash (`\044(…)`),
/// or a wildcard, which matches a name the line made but did not write out
/// (`*`, `?`, `[`, and an extglob's `+(`, `@(`, `!(`).
fn holds_code(name: &str) -> bool {
    name.contains(['$', '`', '\\', '*', '?', '['])
        || ["+(", "@(", "!("].iter().any(|glob| name.contains(glob))
}

/// Whether `unit` makes the shell keep the physical path as its working
/// directory: `cd -P` and `pushd -P`, `set -P`, `set -o physical`, `shopt -so
/// physical`, and a bash that starts with the same option. Read loosely: an
/// option turned off again still counts.
fn makes_physical(unit: &Unit) -> bool {
    let Some(key) = unit.key() else {
        return false;
    };
    if !matches!(
        key.as_str(),
        "cd" | "chdir" | "pushd" | "set" | "shopt" | "bash" | "sh"
    ) {
        return false;
    }
    has_flag(&unit.args, Some('P'), None)
        || (!matches!(key.as_str(), "cd" | "chdir" | "pushd")
            && unit.args.iter().any(|arg| arg.known() == Some("physical")))
}

/// The drive a cmd unit switches to: `D:` is read as the program `D` given
/// `:`.
fn cmd_drive_switch(unit: &Unit) -> Option<char> {
    let program = unit.program.known()?;
    let mut chars = program.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    (chars.next().is_none() && unit.args.first().and_then(Arg::known) == Some(":"))
        .then_some(letter)
}

/// The folders in `elsewhere` and `stayed` that are not `dir`, each once,
/// and a folder only known when it runs when the line is `adrift` (see
/// [`Unit::others`]).
fn others(
    dir: Option<&Arg>,
    elsewhere: &[Option<Arg>],
    stayed: &[Option<Arg>],
    adrift: bool,
) -> Vec<Option<Arg>> {
    let lost = adrift.then(|| {
        Some(Arg::Unknown(
            "where a cd that may have failed left the line".to_string(),
        ))
    });
    let mut folders: Vec<Option<Arg>> = Vec::new();
    for folder in elsewhere.iter().chain(stayed).cloned().chain(lost) {
        if !same_folder(folder.as_ref(), dir)
            && !folders
                .iter()
                .any(|known| same_folder(known.as_ref(), folder.as_ref()))
        {
            folders.push(folder);
        }
    }
    folders
}

/// Every index in `ranges`, each once and in order, however they overlap.
fn joined(ranges: impl Iterator<Item = Range<usize>>) -> impl Iterator<Item = usize> {
    let mut ranges: Vec<Range<usize>> = ranges.filter(|range| !range.is_empty()).collect();
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged.into_iter().flatten()
}

/// Where a pass of a loop or a call of a function before a unit may have
/// left the line (see [`Unit::again`]).
const AGAIN: &str = "where a pass or a call before it left the line";

/// Whether `a` and `b` are the same folder to judge a path from: the same
/// one, or two only known when they run, from which every relative path is
/// only known when it runs too, whatever their text says.
fn same_folder(a: Option<&Arg>, b: Option<&Arg>) -> bool {
    a == b || matches!((a, b), (Some(a), Some(b)) if a.known().is_none() && b.known().is_none())
}

/// The folder `folder` names, with the `..` a `cd` folds folded under the
/// rules of `folds`, the shell whose spelling it is (`None`: not folded), so
/// two spellings of one folder compare equal, as do any two only known when
/// they run; `None` is where the line began.
fn folder_key(folder: Option<&Arg>, folds: Option<Shell>) -> Option<Cow<'_, Arg>> {
    match (folder, folds) {
        // Every folder only known when it runs is one (see [`same_folder`]).
        (Some(folder), _) if folder.known().is_none() => {
            Some(Cow::Owned(Arg::Unknown(String::new())))
        }
        (Some(Arg::Known(text)), Some(shell)) if text.contains("..") => {
            match fold_dots(text, shell) {
                Some(folded) if matches!(folded.as_str(), "" | ".") => None,
                Some(folded) => Some(Cow::Owned(Arg::Known(folded))),
                None => folder.map(Cow::Borrowed),
            }
        }
        _ => folder.map(Cow::Borrowed),
    }
}

/// Whether `unit` may turn on bash's `cdable_vars` or zsh's `cdablevars`
/// (`shopt -s cdable_vars`, `setopt CDABLE_VARS`, `set -o cdablevars`,
/// `unsetopt nocdablevars`): any word that names it, however zsh spells it,
/// whichever way it is switched, or an option only known when it runs.
fn cdable(unit: &Unit) -> bool {
    let Some(key) = unit.key() else {
        return false;
    };
    if !matches!(key.as_str(), "shopt" | "setopt" | "unsetopt" | "set") {
        return false;
    }
    unit.args.iter().any(|arg| match arg.known() {
        Some(text) => {
            let name: String = text
                .chars()
                .filter(|c| *c != '_')
                .collect::<String>()
                .to_ascii_lowercase();
            let name = name.trim_start_matches(['-', '+']);
            matches!(name, "cdablevars" | "nocdablevars")
        }
        None => key != "set",
    })
}

/// Where a POSIX `cd` or `pushd` to `target` goes when the line sets
/// `CDPATH`: a relative name that does not start with `.` or `..` is looked
/// up in each folder `CDPATH` names before the working folder, so it goes to
/// a place only known when it runs. So it does with `cdable_vars` on (see
/// [`Split::cdable`]), which takes a name that is not a folder for a
/// variable that holds one.
fn by_cdpath(unit: &Unit, target: Arg) -> Arg {
    let searched = matches!(unit.key().as_deref(), Some("cd" | "chdir" | "pushd"))
        && target.known().is_some_and(|text| {
            let first = text.split('/').next().unwrap_or_default();
            !text.is_empty() && !matches!(first, "" | "." | "..") && !text.starts_with('~')
        });
    match target {
        Arg::Known(text) if searched => Arg::Unknown(text),
        other => other,
    }
}

/// Whether a `cd` to `target` only steps up (`..`, `../..`) or stays (`.`):
/// it goes back through folders the shell came through, so it is taken as
/// run (see [`Split::stayed`]).
fn steps_up(target: &Arg, shell: Shell) -> bool {
    let separators: &[char] = if shell == Shell::Posix {
        &['/']
    } else {
        &['/', '\\']
    };
    target.known().is_some_and(|text| {
        !text.is_empty()
            && text
                .split(separators)
                .all(|step| matches!(step, "" | "." | ".."))
            && !text.starts_with(separators)
    })
}

/// Whether a name follows a `..` in the POSIX path `text`.
fn names_after_dots(text: &str) -> bool {
    text.split('/')
        .skip_while(|part| *part != "..")
        .any(|part| !matches!(part, "" | "." | ".."))
}

/// Whether the folder `text`, the `cd`s joined, is spelt longer than
/// [`MAX_DIR_LEN`] or deeper than [`MAX_DIR_PARTS`].
fn too_long(text: &str) -> bool {
    text.len() > MAX_DIR_LEN || text.matches(['/', '\\']).count() > MAX_DIR_PARTS
}

/// `text`, a folder the `cd`s joined, with each `..` after a name folded
/// into it (`a/b/../..` is `.`), as a `cd` folds it, and each empty part
/// past the first dropped. The part after a root (`/`, `C:`, `~`) is not
/// folded, so the folder stays one below it. `None` for a text the walk does
/// not fold: one that starts with two separators (`\\server\share`, `//x`)
/// or names a provider path (`a::b`).
fn fold_dots(text: &str, shell: Shell) -> Option<String> {
    let separator = |c: char| c == '/' || (shell != Shell::Posix && c == '\\');
    let mut chars = text.chars();
    if text.contains("::")
        || (chars.next().is_some_and(separator) && chars.next().is_some_and(separator))
    {
        return None;
    }
    // Each part, with the separator written before it.
    let mut parts: Vec<(Option<char>, &str)> = Vec::new();
    let (mut start, mut before) = (0, None);
    for (at, c) in text.char_indices().filter(|(_, c)| separator(*c)) {
        parts.push((before, &text[start..at]));
        (start, before) = (at + c.len_utf8(), Some(c));
    }
    parts.push((before, &text[start..]));
    let root = parts
        .first()
        .is_some_and(|(_, part)| part.is_empty() || part.contains([':', '~']));
    let folds = |part: &str| {
        !matches!(part, "" | "." | "..") && !part.contains(['~', ':', '$', '*', '?', '[', '{', '`'])
    };
    let mut kept: Vec<(Option<char>, &str)> = Vec::with_capacity(parts.len());
    for (at, (before, part)) in parts.into_iter().enumerate() {
        if at > 0 && part.is_empty() {
            continue;
        }
        let after_root = root && kept.len() == 1;
        if part == ".." && !after_root && kept.last().is_some_and(|(_, last)| folds(last)) {
            kept.pop();
        } else {
            kept.push((before, part));
        }
    }
    let mut folded = String::with_capacity(text.len());
    for (at, (before, part)) in kept.into_iter().enumerate() {
        if at > 0 {
            folded.push(before.unwrap_or('/'));
        }
        folded.push_str(part);
    }
    if folded.is_empty() {
        folded.push('.');
    }
    Some(folded)
}

/// Where a `cd` (`pushd`, `Set-Location`) moves to, when `unit` is one.
pub(crate) fn moves_to(unit: &Unit) -> Option<Arg> {
    // What a package runner starts is a program (`npx cd src`), not the
    // shell's builtin: it cannot move the shell.
    if unit
        .wrappers
        .iter()
        .any(|wrapper| crate::launch::RUNNERS.contains(&wrapper.as_str()))
    {
        return None;
    }
    // A block or a script run by a name only known when it runs may hold a
    // `cd` of the session.
    if unit.relocates {
        return Some(Arg::Unknown(unit.program.text().to_string()));
    }
    let program = unit.program.known()?;
    let lower = program.to_ascii_lowercase();
    // `D:` moves to another drive, whose current folder the line does not
    // show: cmd reads it as the program `D` given `:`, PowerShell as a
    // function named `D:`.
    let drive = match unit.shell {
        Shell::Cmd => cmd_drive_switch(unit).is_some(),
        Shell::PowerShell => {
            lower.len() == 2
                && lower.ends_with(':')
                && lower.starts_with(|c: char| c.is_ascii_alphabetic())
        }
        Shell::Posix => false,
    };
    if drive {
        return Some(Arg::Unknown(format!("{}:", &lower[..1])));
    }
    // `cd..` and `cd\`: cmd and PowerShell read them as one program name.
    // A cmd name that names a program file (`cd.\a\b.bat`) is that file,
    // which runs and leaves the line where it was.
    if unit.shell == Shell::PowerShell
        || (unit.shell == Shell::Cmd && !crate::cmd::names_program(program))
    {
        for verb in ["chdir", "cd"] {
            if lower
                .strip_prefix(verb)
                .is_some_and(|rest| rest.starts_with(['.', '\\', '/']))
            {
                return Some(Arg::Known(program[verb.len()..].to_string()));
            }
        }
    }
    let key = unit.key()?;
    match (unit.shell, key.as_str()) {
        (Shell::Posix, "cd" | "chdir") => match operands(&unit.args, &[]).first() {
            Some(Arg::Known(dash)) if dash == "-" => Some(Arg::Unknown(dash.clone())),
            Some(target) => Some((*target).clone()),
            None => Some(Arg::Known("~".to_string())),
        },
        (Shell::Posix, "pushd") => pushd_target(&unit.args, &key),
        (Shell::Posix | Shell::Cmd, "popd") | (Shell::PowerShell, "pop-location") => {
            Some(Arg::Unknown(key))
        }
        (Shell::Cmd, "cd" | "chdir" | "pushd") => {
            plain(&unit.args).first().map(|target| (*target).clone())
        }
        (Shell::PowerShell, "set-location" | "push-location") => location_target(unit, key),
        // A string the line writes out is read as a script run in the
        // session (see `launch`), whose `cd` moves the line; any other may
        // hold one the guard does not see.
        (Shell::PowerShell, "invoke-expression") => {
            let params = crate::powershell::Params::read(&unit.args);
            match params
                .values(&["command"])
                .first()
                .or(params.positional.first())
            {
                Some(Arg::Known(_)) if !unit.downloaded => None,
                Some(script) => Some(Arg::Unknown(script.text().to_string())),
                None => Some(Arg::Unknown(key)),
            }
        }
        _ => None,
    }
}

/// Where a PowerShell `Set-Location` or `Push-Location` moves to, `None`
/// when it does not move: read by their own parameters, so the value of
/// `-StackName` is not the folder. `--` ends the parameters, so it is not
/// the path: `cd -- -` is the history step and `cd -- X` goes to X. With no
/// path, a stage after the first takes it from the pipeline; the first
/// `Set-Location` goes home, a `Set-Location -StackName` only picks the stack
/// `Pop-Location` takes from, and a `Push-Location` saves where the line is
/// and stays there.
fn location_target(unit: &Unit, key: String) -> Option<Arg> {
    let params = crate::powershell::Params::cmdlet(&unit.args, &crate::powershell::LOCATION);
    let mut positional = params.positional.iter().copied();
    let end = params
        .positional
        .iter()
        .position(|arg| arg.known() == Some("--"));
    let first = match end {
        Some(0) => positional.nth(1),
        _ => positional.next(),
    };
    let target = params
        .values(&["path", "literalpath"])
        .first()
        .copied()
        .or(first)
        .map(|target| match target {
            // PowerShell 6.2+ reads `-` and `+` as a step back or forward in
            // location history, not a folder.
            Arg::Known(step) if step == "-" || step == "+" => Arg::Unknown(step.clone()),
            other => other.clone(),
        });
    if target.is_some() {
        return target;
    }
    if unit.stage.is_some_and(|stage| stage.index > 0) {
        Some(Arg::Unknown(key))
    } else if key == "push-location" || params.has(&["stackname"]) {
        None
    } else {
        Some(Arg::Known("~".to_string()))
    }
}

/// Whether `unit`, a PowerShell command whose name is `key`, sets an alias
/// that may stand in for a location cmdlet: one named as one (`Set-Alias
/// popd Get-Date`), one that stands for one under another name, or one whose
/// name is only known when it runs (`Set-Alias $n …`, `Import-Alias`).
fn renames_location(unit: &Unit, key: &str) -> bool {
    match key {
        "set-alias" | "new-alias" | "sal" | "nal" => unit.args.iter().any(|arg| match arg {
            Arg::Known(word) => crate::powershell::names_location(word),
            _ => true,
        }),
        "import-alias" | "ipal" => true,
        _ => false,
    }
}

/// Where a POSIX `pushd` moves to, `None` when it does not move.
///
/// Its options come before the folder, as `cd`'s do: `-n` (the stack is
/// changed and the shell stays where it is), and `-L` and `-P` (how a link
/// in the folder is followed, which a shell may take and another refuse:
/// read as taken). Neither is the folder. What names no folder is not
/// guessed at: `pushd` alone swaps the top of the stack, `pushd +1` and
/// `pushd -1` rotate it, `-` goes back, and an option the guard does not
/// know (`-q`, `--help`) or a word only known when the line runs may be
/// any of them, so the folder is only known when it runs. `--` ends the
/// options.
fn pushd_target(args: &[Arg], key: &str) -> Option<Arg> {
    let mut stays = false;
    let mut rest = args.iter();
    // What the line moves to when `word` is the last the guard reads: not
    // at all after `-n`, else to `word`.
    let then = |stays: bool, word: Arg| (!stays).then_some(word);
    while let Some(arg) = rest.next() {
        let Some(text) = arg.known() else {
            return then(stays, Arg::Unknown(arg.text().to_string()));
        };
        if text == "--" {
            let folder = rest.next().cloned();
            return then(
                stays,
                folder.unwrap_or_else(|| Arg::Unknown(key.to_string())),
            );
        }
        let flags = text.strip_prefix('-').filter(|flags| !flags.is_empty());
        if flags.is_some_and(|flags| flags.chars().all(|c| matches!(c, 'n' | 'L' | 'P'))) {
            stays |= flags.is_some_and(|flags| flags.contains('n'));
        } else if text.starts_with(['-', '+']) {
            // A stack index, `-` (the folder before), or an option unknown.
            return then(stays, Arg::Unknown(text.to_string()));
        } else {
            return then(stays, arg.clone());
        }
    }
    then(stays, Arg::Unknown(key.to_string()))
}

/// How deep shells may start shells (`bash -c "sh -c '…'"`) before the line
/// is too nested to read.
pub(crate) const MAX_DEPTH: usize = 8;

/// How deep a parse tree is walked before the line is too nested to read:
/// walking deeper would risk overflowing the stack.
pub(crate) const MAX_TREE_DEPTH: usize = 400;

/// The longest line read: past it, the line is not read at all.
pub(crate) const MAX_LEN: usize = 64 * 1024;

/// The most nested script text read for one line, in bytes, with the parts
/// of the line read again (see [`read_again`]): past it, the line is
/// unreadable. A nested script is read once for each time the line starts
/// it, so this bounds the work whatever the nesting does. It is a
/// few times the longest line, which a plain line never nears.
const MAX_NESTED_READ: usize = 4 * MAX_LEN;

/// How much the grammars' lexers may read for a line before the parse is
/// stopped and the text is unreadable: [`MAX_LEXED_BASE`] bytes, and
/// [`MAX_LEXED`] times the text parsed for the line (its scripts and inline
/// code too), in the bytes the grammar is handed: [`LEXED_PIECE`] at a time,
/// so what its lexer reads, again or for the first time, is counted to
/// within a piece. That needs no clock, so the answer is the same on every
/// machine.
///
/// A line a person or an agent writes is read once or twice over, and a few
/// shapes a few hundred times over a short text (cmd's chain of 400
/// commands, its brackets 400 deep, a here-document after a long group):
/// under a megabyte. The noise that stalls a grammar goes back over the rest
/// of the line at every token, and reads gigabytes at the length limit (a
/// lexer reads a megabyte in a few milliseconds).
const MAX_LEXED: usize = 32;

/// See [`MAX_LEXED`].
const MAX_LEXED_BASE: usize = 4 * 1024 * 1024;

/// The most bytes the grammar is handed at once (more only to end where a
/// character does): see [`MAX_LEXED`].
const LEXED_PIECE: usize = 256;

/// The most folders a redirect is placed from for the calls it covers to
/// functions that move the line: each is a place the redirect is judged
/// from, and a line that calls more than this many (each from another
/// folder) under one redirect is unknown, not read from them all.
const MAX_CALL_STARTS: usize = 32;

/// The most other folders the line is kept as maybe being in (see
/// [`Split::elsewhere`]): each is a folder a run of a file the line wrote is
/// judged from, and past this many the line may be anywhere, so such a run is
/// unknown.
const MAX_ELSEWHERE: usize = 8;

/// The longest spelling of the folder the line is in that is followed (the
/// `cd`s joined, `a/b/../c`), in bytes and in separators. Every path the rules
/// read after a `cd` is read from that folder, so its length is paid once for
/// each, and a line that went one folder down at every `cd` would pay for all
/// its `cd`s again at every path. A spelling past either is folded as a `cd`
/// folds it, each `..` after a name taken off with the name (`a/../a/..` is
/// `.`), so going down and back up costs nothing; past either still, or when
/// a `cd` may have followed a link physically (`cd -P`, `cd link/../etc`), the
/// folder is only known when it runs. 1,024 bytes is the longest path macOS
/// opens (`PATH_MAX`), and no real folder is 128 deep.
const MAX_DIR_LEN: usize = 1024;

/// See [`MAX_DIR_LEN`].
const MAX_DIR_PARTS: usize = 128;

/// The most functions that move the line or whose definition is redirected
/// that a line may define (a name defined again counts again, kept or
/// replaced) before the line is unknown instead of placed call by call from
/// where each function was defined: a line that defines more is not one a
/// person wrote to be read call by call, and it bounds what a call has to
/// look through.
const MAX_MOVING_FUNCTIONS: usize = 256;

/// The most bodies kept apart for one function or alias name (see
/// [`Split::body`]): a name defined again runs the last definition, or one of
/// those before it when a later one may not have run. Each body a call may
/// run is followed for the secrets it reads and sends, so the work a line
/// can make stays bounded however often it defines one name; the ones before
/// are kept together, as one range that holds them all.
const MAX_BODIES: usize = 4;

/// Split `command`, started on the drive `drive` with home on `home_drive`;
/// `effect` says it is also read for [`crate::effect`].
pub(crate) fn split(
    command: &str,
    shell: Shell,
    (drive, home_drive): (Option<char>, Option<char>),
    effect: bool,
) -> Split {
    let mut split = Split::default();
    start(&mut split, false, (drive, home_drive));
    split.kept.on = effect;
    script(&mut split, command, shell, 0);
    if split.psdrive {
        // A drive the line makes may be entered before the text that makes
        // it (a function body, a loop), so read the line again knowing it.
        start(&mut split, true, (drive, home_drive));
        script(&mut split, command, shell, 0);
    }
    // A function body or a loop may run after the line turns `extendedglob`
    // on, wherever it is written: read the line again, reading their words
    // with it on.
    if split.ever_extended
        && !(split.in_body.is_empty()
            && split.write_in_body.is_empty()
            && split.read_in_body.is_empty())
    {
        start_again_extended(&mut split);
        script(&mut split, command, shell, 0);
    }
    split.hide_bodies();
    split.settle_later();
    split.settle_bodies();
    split.settle_functions();
    split.settle_pwd();
    split
}

/// Start `split` afresh for a read of the line from the drive `drive` with
/// home on `home_drive`; `psdrive` says the read knows the drives the line
/// makes. A function of its own, as [`start_again_extended`] is, so that the
/// `Split` it builds is not held on the stack while [`split`] reads the line:
/// the walk of a deeply nested line needs all of it.
#[inline(never)]
fn start(split: &mut Split, psdrive: bool, (drive, home_drive): (Option<char>, Option<char>)) {
    *split = Split {
        drive,
        home_drive,
        psdrive,
        ..Split::default()
    };
}

/// Clear `split` for a second read of the line that reads the words of its
/// function bodies and loops with `extendedglob` on, keeping what it was
/// started with. A function of its own, so that the `Split` it builds is
/// not held on the stack while [`split`] reads the line: the walk of a
/// deeply nested line needs all of it.
#[inline(never)]
fn start_again_extended(split: &mut Split) {
    let fresh = Split {
        psdrive: split.psdrive,
        extended_bodies: true,
        drive: split.drive,
        home_drive: split.home_drive,
        ..Split::default()
    };
    let effect = split.kept.on;
    *split = fresh;
    split.kept.on = effect;
}

/// Whether `text`, a script or inline code `depth` levels deep, may be read:
/// not nested too deeply, not too long, and not the one that takes the
/// line past the budget of nested text. A finding says why when not.
pub(crate) fn within_limits(split: &mut Split, text: &str, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        split.problem(
            Rule::Unreadable,
            "starts shells inside shells too deeply to read",
            None,
        );
        return false;
    }
    if text.len() > MAX_LEN {
        split.problem(Rule::Unreadable, "is too long to read", None);
        return false;
    }
    depth == 0 || read_again(split, text, "starts too many scripts to read")
}

/// Whether `text`, a part of the line read again as a script of its own
/// (cmd's `ver && if …`, see [`crate::cmd`]), may be read: it is counted
/// against the budget of nested text, so a part that holds another such
/// part, and so on, cannot make the line be read again and again. A
/// finding gives `why` when it may not.
pub(crate) fn read_again(split: &mut Split, text: &str, why: &str) -> bool {
    split.nested_read += text.len() + 1;
    if split.nested_read > MAX_NESTED_READ {
        split.problem(Rule::Unreadable, why, None);
        return false;
    }
    true
}

/// Whether `text`, the value of a variable a program reads as the command
/// it runs (`npm_config_call='…' npx`), may be read as that command once
/// more. A line sets the value once and may run it many times (`npx; npx;
/// …`), each a reading of the whole value: the readings are bounded by the
/// longest line, as they would be had the line written the command out each
/// time (`npx -c '…'; npx -c '…'`). Past it, the line is unreadable.
pub(crate) fn read_from_variable(split: &mut Split, text: &str) -> bool {
    split.variable_read += text.len() + 1;
    if split.variable_read > MAX_LEN {
        split.problem(
            Rule::Unreadable,
            "runs the command a variable sets too many times to read",
            None,
        );
        return false;
    }
    true
}

/// Split `text`, run by `shell`, `depth` shells deep, into `split`.
pub(crate) fn script(split: &mut Split, text: &str, shell: Shell, depth: usize) {
    script_in(split, text, shell, depth, false);
}

/// As [`script`]; `here` says the script runs in this shell, as `eval`'s
/// does, so what it does to the working directory stays.
pub(crate) fn script_in(split: &mut Split, text: &str, shell: Shell, depth: usize, here: bool) {
    if !within_limits(split, text, depth) {
        return;
    }
    if let Some(why) = crate::tangled::too_tangled(text, shell) {
        split.problem(Rule::Unreadable, why, None);
        return;
    }
    if shell == Shell::PowerShell && split.splits_script(text) {
        split.problem(
            Rule::Unknown,
            "runs a script only known when it runs",
            Some(text),
        );
        return;
    }
    // A nested script (`bash -c 'cd x'`) runs in its own process: its `cd`
    // does not move the line that started it, and a function it defines is
    // not the line's. `eval`'s runs in this shell.
    let outer = split.dir_snapshot();
    // Its location stacks are its own, and empty: a `Pop-Location` there
    // does not take what the line saved.
    if !here {
        split.take_locations();
    }
    // (The line itself, at depth 0, is the shell whose functions these are.)
    let apart = !here && depth > 0;
    split.apart += usize::from(apart);
    // A group a `coproc` opens closes in the same script.
    let groups = std::mem::take(&mut split.coproc_groups);
    match shell {
        Shell::Posix => crate::posix::split(split, text, depth),
        Shell::PowerShell => crate::powershell::split(split, text, depth),
        Shell::Cmd => crate::cmd::split(split, text, depth),
    }
    // One it never closes (`coproc {`) is a line the shell does not run
    // as written.
    if std::mem::replace(&mut split.coproc_groups, groups) > 0 {
        split.problem(
            Rule::Unreadable,
            "opens a group that never closes",
            Some("{"),
        );
    }
    split.apart -= usize::from(apart);
    if !here {
        split.restore_dir(outer);
    }
}

/// Parse `text` with `language`; `None` (and a finding) when the parser
/// gives nothing back or reads past its budget (see [`MAX_LEXED`]), and a
/// finding beside the tree when part of it is an error.
pub(crate) fn parse(
    split: &mut Split,
    text: &str,
    language: &tree_sitter::Language,
) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(language).is_err() {
        split.problem(Rule::Unreadable, "cannot be read", None);
        return None;
    }
    let bytes = text.as_bytes();
    // The budget is the line's, shared by every script and piece of code in
    // it, so a line that starts many cannot spend it many times over.
    split.parsed = split.parsed.saturating_add(bytes.len());
    let budget = MAX_LEXED
        .saturating_mul(split.parsed)
        .saturating_add(MAX_LEXED_BASE)
        .saturating_sub(split.lexed);
    // The bytes handed to the grammar so far.
    let lexed = std::cell::Cell::new(0_usize);
    let mut read = |at: usize, _: tree_sitter::Point| -> &[u8] {
        // A piece at a time, ending where a character does: the lexer asks
        // again past each piece, and whenever it goes back before one.
        let end = (at.saturating_add(LEXED_PIECE)..=bytes.len())
            .find(|end| text.is_char_boundary(*end))
            .unwrap_or(bytes.len());
        let piece = bytes.get(at..end).unwrap_or_default();
        lexed.set(lexed.get().saturating_add(piece.len().max(1)));
        piece
    };
    let mut progress = |_: &tree_sitter::ParseState| {
        if lexed.get() > budget {
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(())
        }
    };
    let options = tree_sitter::ParseOptions::new().progress_callback(&mut progress);
    let tree = parser.parse_with_options(&mut read, None, Some(options));
    split.lexed = split.lexed.saturating_add(lexed.get());
    if lexed.get() > budget {
        split.problem(Rule::Unreadable, "takes too long to read", None);
        return None;
    }
    if let Some(tree) = tree {
        if tree.root_node().has_error() {
            split.problem(Rule::Unreadable, "cannot be read in full", None);
        }
        Some(tree)
    } else {
        split.problem(Rule::Unreadable, "cannot be read", None);
        None
    }
}

/// Visit every node under `root`, without recursion, so a deep tree cannot
/// overflow the stack.
pub(crate) fn for_each_node<'tree>(
    root: tree_sitter::Node<'tree>,
    mut visit: impl FnMut(tree_sitter::Node<'tree>),
) {
    let mut cursor = root.walk();
    loop {
        visit(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// Visit the nodes under `root`, without recursion, going into the children
/// of a node only when `visit` says so.
pub(crate) fn for_each_node_until<'tree>(
    root: tree_sitter::Node<'tree>,
    mut visit: impl FnMut(tree_sitter::Node<'tree>) -> bool,
) {
    let mut cursor = root.walk();
    loop {
        if visit(cursor.node()) && cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// The source text of `node`.
pub(crate) fn text<'s>(node: &tree_sitter::Node<'_>, source: &'s str) -> &'s str {
    source.get(node.byte_range()).unwrap_or_default()
}

/// Whether a POSIX-style option is given: `short` in any bundle (`-rf`), or
/// `--long` (also as `--long=value`). Options end at `--`.
pub(crate) fn has_flag(args: &[Arg], short: Option<char>, long: Option<&str>) -> bool {
    for arg in args {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            return false;
        }
        if let Some(name) = text.strip_prefix("--") {
            if long.is_some_and(|long| {
                name == long
                    || name
                        .strip_prefix(long)
                        .is_some_and(|rest| rest.starts_with('='))
            }) {
                return true;
            }
        } else if let Some(bundle) = text.strip_prefix('-') {
            if bundle.starts_with(|c: char| c.is_ascii_alphabetic())
                && short.is_some_and(|short| bundle.contains(short))
            {
                return true;
            }
        }
    }
    false
}

/// Whether `arg`, a value only known when it runs, may be several words when
/// it does, any of which may be an option or another operand: in a POSIX
/// shell an expansion outside quotes (`$f`, `x$f`, `$(…)`, a backtick), which
/// the shell splits, and a quoted one that is a list (`"$@"`, `"${a[@]}"`,
/// `"${!p@}"`); in PowerShell a variable (not `$env:`), a splat (`@a`) or a
/// subexpression, which hand a program each item of an array as its own
/// argument; in cmd a `%X%` or `!X!`, quoted or not, which is put in as
/// text before the program splits its own command line, so a value that
/// holds a `"` ends the quotes around it; and what a pipeline hands a
/// program (`xargs`). A quoted expansion in a POSIX shell or PowerShell is
/// one word (`"$f"`, `"$(…)"`), and so is a known value.
pub(crate) fn may_split(arg: &Arg, shell: Shell) -> bool {
    let text = match arg {
        Arg::Known(_) | Arg::Null => return false,
        Arg::Input => return true,
        Arg::Unknown(text) => text.as_str(),
        Arg::Template { source, .. } => source,
    };
    match shell {
        Shell::Posix => {
            text.contains("$@")
                || text.contains("${@")
                || text.contains("[@]")
                || (text.contains("${!") && text.contains("@}"))
                || unquoted_expansion(text)
        }
        Shell::PowerShell => {
            text.starts_with('(')
                || text.starts_with("@(")
                || (text.starts_with('$')
                    && !text
                        .get(..5)
                        .is_some_and(|head| head.eq_ignore_ascii_case("$env:")))
                || (text.starts_with('@') && text.len() > 1)
        }
        Shell::Cmd => text.contains(['%', '!']),
    }
}

/// Whether a POSIX word holds a `$` or a backtick outside quotes: an
/// expansion the shell splits into words. `$'…'` and `$"…"` are quotes.
fn unquoted_expansion(text: &str) -> bool {
    let mut quote = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(open), c) if c == open => quote = None,
            // A backslash keeps the next character, outside quotes and
            // inside double ones.
            (Some('"') | None, '\\') => {
                chars.next();
            }
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '$') if !matches!(chars.peek(), Some('\'' | '"') | None) => return true,
            (None, '`') => return true,
            _ => {}
        }
    }
    false
}

/// The text an argument only known when it runs is sure to start with,
/// when that makes it an option, one word though it is: its text up to the
/// first expansion, quotes taken off, when that starts with `-` (or `/`, a
/// switch, in cmd): `"-$F"`, `-"$F"`, `"--remove-$X"`. In a POSIX shell
/// also the start of the value a default or an alternate writes out, which
/// is what the word is when the variable is unset or empty (`"${X:---force}"`,
/// `"${X:+--force}"`), and the text of an ANSI-C or locale quote, which the
/// reader keeps as only known when it runs (`$'--force'`, `$"-f"`); an
/// escape that starts an ANSI-C quote may be any character, a `-` among
/// them, and gives the empty start: any option. `None` when the word starts
/// with what an expansion holds (`"$F"`): a rule takes that as a value.
pub(crate) fn option_start(arg: &Arg, shell: Shell) -> Option<String> {
    let start = unknown_start(arg, shell)?;
    let dashes: &[char] = if shell == Shell::Cmd {
        &['-', '/']
    } else {
        &['-']
    };
    (start.is_empty() || start.starts_with(dashes)).then_some(start)
}

/// The text an argument only known when it runs is sure to start with,
/// whatever that is (see [`option_start`]): `+` for `"+$B"`. `None` for a
/// known value, and when nothing is written before the first expansion.
pub(crate) fn unknown_start(arg: &Arg, shell: Shell) -> Option<String> {
    let text = match arg {
        Arg::Unknown(text) => text.as_str(),
        Arg::Template { source, .. } => source,
        Arg::Known(_) | Arg::Null | Arg::Input => return None,
    };
    match shell {
        Shell::Posix => posix_start(text),
        Shell::PowerShell => Some(literal_start(text, '`', &['$', '@', '('])),
        Shell::Cmd => Some(literal_start(text, '^', &['%', '!'])),
    }
}

/// The start of a POSIX word up to its first expansion, quotes taken off
/// (see [`option_start`]). `None` when nothing is written before it and no
/// default writes it out.
fn posix_start(text: &str) -> Option<String> {
    let mut start = String::new();
    let mut quote: Option<char> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), c) => start.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '\\') => start.extend(chars.next()),
            // Inside double quotes a backslash keeps only `$`, a backtick,
            // `"` and itself.
            (_, '\\') => match chars.next() {
                Some(next @ ('$' | '`' | '"' | '\\')) => start.push(next),
                Some(next) => {
                    start.push('\\');
                    start.push(next);
                }
                None => start.push('\\'),
            },
            (_, '$') => match chars.peek() {
                // ANSI-C quoting: its text, up to an escape.
                Some('\'') if quote.is_none() => {
                    chars.next();
                    loop {
                        match chars.next() {
                            Some('\'') | None => break,
                            Some('\\') => return Some(start),
                            Some(c) => start.push(c),
                        }
                    }
                }
                // Locale quoting reads as double quotes.
                Some('"') if quote.is_none() => {
                    chars.next();
                    quote = Some('"');
                }
                Some('{') if start.is_empty() => {
                    chars.next();
                    let mut depth = 1;
                    let inner: String = chars
                        .by_ref()
                        .take_while(|&c| {
                            match c {
                                '{' => depth += 1,
                                '}' => depth -= 1,
                                _ => {}
                            }
                            depth > 0
                        })
                        .collect();
                    return default_start(&inner);
                }
                _ => break,
            },
            (_, '`') => break,
            (_, c) => start.push(c),
        }
    }
    (!start.is_empty()).then_some(start)
}

/// The start of the value a `${NAME:-word}`, `${NAME-word}`, `${NAME:=word}`
/// or `${NAME:+word}` writes out, `inner` being what is between its braces.
fn default_start(inner: &str) -> Option<String> {
    let name = inner
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(inner.len());
    if name == 0 {
        return None;
    }
    let rest = &inner[name..];
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    let word = rest.strip_prefix(['-', '=', '+'])?;
    posix_start(word)
}

/// The start of a PowerShell or cmd word up to its first expansion, quotes
/// taken off, `escape` keeping the character after it (see
/// [`option_start`]).
fn literal_start(text: &str, escape: char, expansions: &[char]) -> String {
    let mut start = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {}
            c if c == escape => start.extend(chars.next()),
            c if expansions.contains(&c) => break,
            c => start.push(c),
        }
    }
    start
}

/// Whether an argument before `--` that is only known when it runs may be an
/// option `could` takes, given the start of its text (see [`option_start`]):
/// one that may split into words when it runs (see [`may_split`]) may be
/// any option.
pub(crate) fn may_be_option(args: &[Arg], shell: Shell, could: impl Fn(&str) -> bool) -> bool {
    args.iter()
        .take_while(|arg| arg.known() != Some("--"))
        .any(|arg| {
            may_split(arg, shell) || option_start(arg, shell).is_some_and(|start| could(&start))
        })
}

/// Whether an argument before `--` that is only known when it runs may be
/// any option (see [`may_be_option`]): a rule that looks for an option that
/// destroys takes it as given.
pub(crate) fn unread_option(args: &[Arg], shell: Shell) -> bool {
    may_be_option(args, shell, |_| true)
}

/// Whether the POSIX-style option `-short` or `--long` may start with
/// `start` (see [`option_start`]): `-` and a bundle of letters may go on
/// with `short`, and `--` with the letters of `long` or a prefix of them,
/// which a program that takes an abbreviation reads as it. The empty start
/// and `-` alone, which a second `-` may follow, may be any option.
pub(crate) fn could_be(start: &str, short: Option<char>, long: Option<&str>) -> bool {
    if start.is_empty() || start == "-" {
        return short.is_some() || long.is_some();
    }
    if let Some(name) = start.strip_prefix("--") {
        return long.is_some_and(|long| {
            long.starts_with(name)
                || name
                    .strip_prefix(long)
                    .is_some_and(|rest| rest.starts_with('='))
        });
    }
    start
        .strip_prefix('-')
        .is_some_and(|bundle| short.is_some() && bundle.chars().all(|c| c.is_ascii_alphanumeric()))
}

/// How an option is given: written out, maybe (by an argument only known
/// when it runs, see [`may_be_option`]), or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flagged {
    Absent,
    Unread,
    Written,
}

impl Flagged {
    /// `Written` when `written`, else `Unread` when `unread`.
    pub(crate) fn of(written: bool, unread: bool) -> Self {
        if written {
            Self::Written
        } else if unread {
            Self::Unread
        } else {
            Self::Absent
        }
    }
}

/// How the POSIX-style option `-short` or `--long` is given: written out
/// ([`has_flag`]), or maybe, by an argument before `--` only known when it
/// runs that may be it (see [`may_be_option`] and [`could_be`]).
pub(crate) fn flagged(
    args: &[Arg],
    shell: Shell,
    short: Option<char>,
    long: Option<&str>,
) -> Flagged {
    Flagged::of(
        has_flag(args, short, long),
        may_be_option(args, shell, |start| could_be(start, short, long)),
    )
}

/// The arguments that are not POSIX-style options: everything after `--`,
/// and what does not start with `-` before it. `takes_value` names the
/// options whose next argument is their value, not an operand.
pub(crate) fn operands<'a>(args: &'a [Arg], takes_value: &[&str]) -> Vec<&'a Arg> {
    operands_where(args, takes_value, |_| false)
}

/// As [`operands`], with the value of an option in `takes_value` among them
/// when it may split into words when it runs (`shred -n $N f`, see
/// [`may_split`]): a word after the first is an operand.
pub(crate) fn operands_split<'a>(
    args: &'a [Arg],
    takes_value: &[&str],
    shell: Shell,
) -> Vec<&'a Arg> {
    operands_where(args, takes_value, |value| may_split(value, shell))
}

/// The operands as [`operands`] reads them, and each value of an option in
/// `takes_value` that `counts` takes as one.
fn operands_where<'a>(
    args: &'a [Arg],
    takes_value: &[&str],
    counts: impl Fn(&Arg) -> bool,
) -> Vec<&'a Arg> {
    let mut operands = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("--") => {
                operands.extend(iter);
                break;
            }
            Some(text) if text.len() > 1 && text.starts_with('-') => {
                if takes_value.contains(&text) {
                    operands.extend(iter.next().filter(|value| counts(value)));
                }
            }
            _ => operands.push(arg),
        }
    }
    operands
}

/// Whether a `/X`-style switch is given, without case, also inside a run
/// like `/s/q`.
pub(crate) fn has_switch(args: &[Arg], name: &str) -> bool {
    args.iter().filter_map(Arg::known).any(|text| {
        text.starts_with('/')
            && text.split('/').skip(1).any(|switch| {
                switch
                    .split(':')
                    .next()
                    .is_some_and(|switch| switch.eq_ignore_ascii_case(name))
            })
    })
}

/// Whether `text` is a `/X`-style switch, not a path: a slash and a switch
/// name (`/q`, `/-y`, `/?`, `/mir`), or a run of short ones (`/s/q`), each
/// with an optional `:value` (`/a:-d`, `/R:3`, `/a:h/s/q`). A name is
/// letters, digits, `-`, `+` and `?`; in a run each is at most [`RUN_NAME`]
/// characters, so `/evil/share/x` is a path with folders.
///
/// Anything else is a path, which can only be judged more strictly than a
/// switch: a text that starts with two separators (`//server/share`,
/// `//?/C:/x`, `/\server`), one core reads as a share or a device
/// (`/dev/sda`), and one with a `\` or a `.` in it. So is a switch whose
/// value starts with a drive or runs on into a path (`/x:C:/Windows`,
/// `/x://evil/s`): its value is a path, and the argument is judged as one.
pub(crate) fn is_switch(text: &str) -> bool {
    switch_names(text).is_some()
}

/// The names of the switches `text` is, in order (`/a:h/s/q` is `a`, `s` and
/// `q`), when it is one by [`is_switch`]; `None` for a path.
pub(crate) fn switch_names(text: &str) -> Option<Vec<&str>> {
    use milo_guards_core::{spelling, Flavour};
    let body = text.strip_prefix('/')?;
    if body.is_empty()
        || body.starts_with(['/', '\\'])
        || text.contains(['\\', '.'])
        || spelling::network(text, Flavour::Windows)
        || spelling::device(text, Flavour::Windows).is_some()
    {
        return None;
    }
    let drive = |value: &str| {
        let mut chars = value.chars();
        chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.next() == Some(':')
    };
    let parts: Vec<&str> = body.split('/').collect();
    let run = parts.len() > 1;
    parts
        .into_iter()
        .map(|part| {
            let (name, value) = match part.split_once(':') {
                Some((name, value)) => (name, Some(value)),
                None => (part, None),
            };
            let named = !name.is_empty()
                && (!run || name.chars().count() <= RUN_NAME)
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '+' | '?'));
            (named && !value.is_some_and(drive)).then_some(name)
        })
        .collect()
}

/// The longest name of a switch written in a run of several (`/s/q`,
/// `/mir/np`): a longer part makes the text a path with folders.
const RUN_NAME: usize = 3;

/// The value of a `/NAME:value` switch whose name is one of `names`, without
/// case (`/LOG:C:\x.txt`, `/exclude:list.txt`): a value that is a path, which
/// [`is_switch`] leaves to be judged as one.
pub(crate) fn switch_value<'a>(text: &'a str, names: &[&str]) -> Option<&'a str> {
    let (name, value) = text.strip_prefix('/')?.split_once(':')?;
    names
        .iter()
        .any(|known| name.eq_ignore_ascii_case(known))
        .then_some(value)
}

/// The arguments that are not `/X`-style switches.
pub(crate) fn plain(args: &[Arg]) -> Vec<&Arg> {
    args.iter()
        .filter(|arg| !arg.known().is_some_and(is_switch))
        .collect()
}
