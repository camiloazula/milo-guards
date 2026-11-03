//! A command line split into units, one per program it runs, whichever
//! grammar split it; and the helpers that read a unit's arguments.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::rc::Rc;

use crate::dotglob;
use crate::effect::Kind;
use crate::startup::{self, Startup};
use crate::{Finding, Rule, Shell};

/// One argument as the program receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
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
        /// The argument as written, quotes and all.
        source: String,
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
            Self::Known(text) | Self::Unknown(text) | Self::Template { source: text, .. } => text,
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
    /// How many levels deep the script it came from is nested: `0` for the
    /// line itself, one more for each `bash -c`, `eval` or `cmd /c`, and one
    /// more for a part of the line the grammar reads again (what follows the
    /// `&&` in cmd's `set X=1 && del y`, the stage after PowerShell's `--%`).
    /// It is what the depth limit counts.
    pub(crate) depth: usize,
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
            hidden: false,
            startup: Rc::default(),
            repeated: false,
            downloaded: false,
            listings: Vec::new(),
            unread_item: false,
            listed: Vec::new(),
            depth: 0,
        }
    }

    pub(crate) fn scope(&self) -> Scope<'_> {
        Scope {
            dir: self.dir.as_ref(),
            hidden: self.hidden,
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
pub(crate) fn key(program: &str, shell: Shell) -> String {
    let base = program.rsplit(['/', '\\']).next().unwrap_or(program);
    let lower = base.to_ascii_lowercase();
    let stem = [".exe", ".com", ".bat", ".cmd"]
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

/// A write a redirect makes: `> file`, `>> file`.
#[derive(Debug, Clone)]
pub(crate) struct Write {
    pub(crate) shell: Shell,
    pub(crate) target: Arg,
    /// As [`Unit::dir`].
    pub(crate) dir: Option<Arg>,
    /// As [`Unit::hidden`].
    pub(crate) hidden: bool,
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Hidden {
    bash: bool,
    zsh: bool,
}

impl Hidden {
    const ON: Self = Self {
        bash: true,
        zsh: true,
    };

    fn any(self) -> bool {
        self.bash || self.zsh
    }

    /// Either shell's flag on in `self` or `other`.
    pub(crate) fn or(self, other: Self) -> Self {
        Self {
            bash: self.bash || other.bash,
            zsh: self.zsh || other.zsh,
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
    /// The folder a unit starts in (as [`Unit::dir`]; `None`: where the
    /// line began).
    Start(Option<Arg>),
    /// The folder a unit starts in, and also where the line is when the
    /// redirect is read (where the unit goes): the folder the unit starts in
    /// is not certain, because its body runs more than once or an earlier
    /// `cd` may not have moved the line, so either may be the one.
    Both(Option<Arg>),
    /// Any of these folders, and also where the line is when the redirect is
    /// read: a call to a function whose body moves the line starts in the
    /// folder the line is in when it is called, which is not known; the
    /// folders it was defined in are the ones the walk can name.
    Among(Vec<Option<Arg>>),
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
    /// [`Chain::stops`]). Only a run of a
    /// file is judged from them (see [`Unit::elsewhere`]): a file written
    /// before such a `cd` and run after it may be the one the line runs. At
    /// most [`MAX_ELSEWHERE`]; past that, one folder only known when it
    /// runs.
    elsewhere: Vec<Option<Arg>>,
    /// The folders the line is still in when a plain `cd` failed: one that
    /// is not in a branch, a loop, a function body, a pipeline stage or
    /// behind a wrapper (those are [`Self::elsewhere`]'s), read after the
    /// line wrote a file. A `cd` to a folder that is not there prints an
    /// error and the shell (POSIX, cmd, PowerShell) runs the next command
    /// where it was, so a file written before it and run after it may be the
    /// one the line runs. Only that
    /// judgement reads these (see [`Unit::stayed`]): where paths are placed,
    /// redirects and every other check take the `cd` as run. Each is moved on
    /// by every `cd` read since; a command on the right side of `&&` after
    /// the `cd` runs only when it ran, so the list keeps them until it ends
    /// (see [`Chain::stayed`]). A `cd` that only steps up (`cd ..`) goes back
    /// through a folder the line came through and is taken as run. At most
    /// [`MAX_ELSEWHERE`]; past that, each file written so far is judged by
    /// its name (see [`Self::written_by_name`]) and none are kept.
    stayed: Vec<Option<Arg>>,
    /// How many of `writes`, and of `units`, have been judged by their name
    /// when the folders in [`Self::stayed`] were too many.
    named_writes: usize,
    named_units: usize,
    /// The folders the last unit added to [`Self::stayed`], when it is a
    /// plain `cd`: the right side of `&&` after it runs only when it ran.
    last_stayed: Vec<Option<Arg>>,
    /// Whether the line has written a file so far: a redirect, or a command
    /// that writes one. Before that, a plain `cd` that failed leaves no file
    /// written where the line stayed.
    wrote: bool,
    /// The units that move the line from a folder that is not certain (see
    /// [`Self::maybe_moved`]; a loop or a function body runs again from where
    /// its last `cd` went), by their place in `units`.
    unsure_starts: HashSet<usize>,
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
    /// The characters a backtick `u{…}` made in a PowerShell string that are
    /// a space that is not an ASCII one, a dash or a typographic quote: as a
    /// path or an argument each is the text it holds, but a script that holds
    /// one is not. Noted while a string is read, which only borrows the
    /// walker.
    splitting: RefCell<Vec<char>>,
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
    /// Whether the line ever turned the option on, in this shell or in a
    /// script it ran, even if it turned it off again.
    ever_dotglob: bool,
    /// The functions the line defines, for a `GLOBIGNORE=x f` in front of a
    /// call.
    functions: Vec<String>,
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
    /// How much nested script text has been read, in bytes (and one for
    /// each script): a line that makes the same script be read again and
    /// again must come back unreadable, not take forever.
    nested_read: usize,
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
    /// The first `PS4` or `BASH_ENV` value the line wrote with `$PWD` in it,
    /// to judge against every `cd` of the line once it is all read.
    used: Option<String>,
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
        self.moved > 0 && self.reassigned("CDPATH")
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

    /// Add a unit, run where the line has moved to; a `cd` moves the line.
    pub(crate) fn push(&mut self, mut unit: Unit) {
        unit.dir.clone_from(&self.dir);
        unit.elsewhere.clone_from(&self.elsewhere);
        unit.stayed.clone_from(&self.stayed);
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
        if let Some(target) = moved {
            self.moves += 1;
            self.moved += 1;
            let dir = self.moved_to(self.dir.as_ref(), &target, unit.shell);
            // Every other folder the line may be in moves too; a `cd` that
            // may not have run also leaves the line where it was.
            let mut elsewhere: Vec<Option<Arg>> = self
                .elsewhere
                .iter()
                .map(|from| Some(self.moved_to(from.as_ref(), &target, unit.shell)))
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
                .map(|from| Some(self.moved_to(from.as_ref(), &target, unit.shell)))
                .collect();
            let mut added = Vec::new();
            if unsure {
                stayed.extend(self.stayed.iter().cloned());
            } else if self.wrote && !steps_up(&target, unit.shell) {
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
        self.wrote = self.wrote || !crate::detect::written_by(&unit).is_empty();
        self.units.push(unit);
    }

    /// Where a `cd` to `target` takes the line from `from`.
    fn moved_to(&self, from: Option<&Arg>, target: &Arg, shell: Shell) -> Arg {
        match crate::path::within(from, target, shell) {
            // Once the line makes a drive, a drive letter may name it: the
            // place is only known when it runs.
            Arg::Known(text) if self.psdrive && crate::path::drive_of(&text).is_some() => {
                Arg::Unknown(text)
            }
            dir => dir,
        }
    }

    /// Say the line may also be in each of `folders` (see
    /// [`Self::elsewhere`]), once each and not where the walk has it; more
    /// than [`MAX_ELSEWHERE`] is one folder only known when it runs.
    fn set_elsewhere(&mut self, folders: Vec<Option<Arg>>) {
        let mut kept: Vec<Option<Arg>> = Vec::new();
        for folder in folders {
            if folder != self.dir && !kept.contains(&folder) {
                kept.push(folder);
            }
        }
        if kept.len() > MAX_ELSEWHERE {
            kept = vec![Some(Arg::Unknown(
                "where a cd that may not have run left the line".to_string(),
            ))];
        }
        self.elsewhere = kept;
    }

    /// Say a plain `cd` that failed may have left the line in each of
    /// `folders` (see [`Self::stayed`]), once each and not where the walk has
    /// it; past [`MAX_ELSEWHERE`], the files written so far are judged by
    /// their name instead (see [`Self::written_by_name`]).
    fn set_stayed(&mut self, folders: Vec<Option<Arg>>) {
        let mut kept: Vec<Option<Arg>> = Vec::new();
        for folder in folders {
            if folder != self.dir && !kept.contains(&folder) {
                kept.push(folder);
            }
        }
        if kept.len() > MAX_ELSEWHERE {
            self.written_by_name();
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
        let redirects = self.writes.get(self.named_writes..).unwrap_or_default();
        let mut named: Vec<Write> = redirects.to_vec();
        for unit in self.units.get(self.named_units..).unwrap_or_default() {
            named.extend(
                crate::detect::written_by(unit)
                    .into_iter()
                    .map(|target| Write {
                        shell: unit.shell,
                        target,
                        dir: unit.dir.clone(),
                        hidden: unit.hidden,
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
        let uses = referenced(value);
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
    /// [`Self::opens_here`]) when the body moves the line, and the folder a
    /// function it calls was defined in when that moves the line.
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
            return if moved { start } else { OpensFrom::Line };
        }
        if moved {
            match start {
                OpensFrom::Start(dir) | OpensFrom::Both(dir) => dirs.push(dir),
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
        // The units are only added to: a range holds the same units each
        // time it is asked for.
        let key = (units.start, units.end);
        let mover = if let Some(mover) = self.starts.get(&key) {
            *mover
        } else {
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
        };
        let Some((index, unit)) =
            mover.and_then(|index| self.units.get(index).map(|unit| (index, unit)))
        else {
            let starts = if by_folder {
                self.function_starts(key.0..key.1, self.moved)
            } else {
                Vec::new()
            };
            return if starts.is_empty() {
                OpensFrom::Line
            } else {
                OpensFrom::Among(starts)
            };
        };
        if self.unsure_starts.contains(&index) {
            OpensFrom::Both(unit.dir.clone())
        } else {
            OpensFrom::Start(unit.dir.clone())
        }
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

    /// Begin a right side of `&&` or `||` in a list; [`Self::link_end`] ends
    /// it. It may not run, so it is a branch. After `&&` it runs only when
    /// the left side did, so the folders a plain `cd` that ends the left side
    /// stayed in when it failed are left for after the list (see
    /// [`Chain::stayed`]).
    pub(crate) fn link_start(&mut self) -> Link {
        let held = std::mem::take(&mut self.last_stayed);
        if !held.is_empty() {
            self.stayed.retain(|folder| !held.contains(folder));
            self.chain.stayed.extend(held);
        }
        self.branches += 1;
        self.links += 1;
        Link {
            moves: self.moves,
            places: self.places(),
        }
    }

    /// End `link`, a right side of `list`: when it moved the line, it may
    /// not have run, so the list may have stopped where the line was before
    /// it, or where the list began, if the left side did not move it. A
    /// command later in the list runs only when this side did, so these are
    /// left for after the list (see [`Chain::stops`]): a chain of `n` `cd`s
    /// leaves the line in at most `n + 1` folders.
    pub(crate) fn link_end(&mut self, list: &List, link: Link) {
        self.branches -= 1;
        self.links -= 1;
        if self.moves != link.moves {
            self.maybe_moved = true;
            self.chain.stops.extend(link.places);
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
    /// it is not certain where the unit it is on starts.
    fn redirect_dirs(&self) -> Vec<Option<Arg>> {
        match &self.opens_from {
            OpensFrom::Line => vec![self.dir.clone()],
            OpensFrom::Start(dir) => vec![dir.clone()],
            OpensFrom::Both(dir) => vec![dir.clone(), self.dir.clone()],
            OpensFrom::Among(dirs) => dirs
                .iter()
                .cloned()
                .chain(std::iter::once(self.dir.clone()))
                .collect(),
        }
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
            OpensFrom::Both(self.dir.clone())
        } else {
            OpensFrom::Start(self.dir.clone())
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

    /// Note that the definition which began at `defining` has been read. A
    /// call to a function whose body moves the line, or that calls one that
    /// does, or whose definition is redirected, starts in a folder the walk
    /// has to work out from where the function was defined.
    pub(crate) fn defined(&mut self, defining: Defining) {
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
        self.wrote = true;
        let hidden = self.hidden();
        for dir in self.redirect_dirs() {
            if self.bodies > 0 {
                self.write_in_body.push(self.writes.len());
            }
            self.writes.push(Write {
                shell,
                target: target.clone(),
                dir,
                hidden,
            });
        }
        // Whether the line may be in more than one folder where the redirect
        // opens: a group's, loop's or branch's opens before its body runs,
        // and one from the folder a unit started in only when that was
        // certain.
        let unsure = match &self.opens_from {
            OpensFrom::Line => !self.elsewhere.is_empty(),
            OpensFrom::Start(_) => false,
            OpensFrom::Both(_) | OpensFrom::Among(_) => true,
        };
        if unsure {
            self.unsure_writes.push(Write {
                shell,
                target,
                dir: self.dir.clone(),
                hidden,
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
        for dir in self.redirect_dirs() {
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
        self.dotglob = Hidden::ON;
        self.ever_dotglob = true;
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
        }
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
    if unit.shell != Shell::Posix {
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
        (Shell::PowerShell, "set-location" | "push-location") => {
            let params = crate::powershell::Params::read(&unit.args);
            // `--` ends the parameters, so it is not the path: `cd -- -` is
            // the history step and `cd -- X` goes to X.
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
                    // PowerShell 6.2+ reads `-` and `+` as a step back or
                    // forward in location history, not a folder.
                    Arg::Known(step) if step == "-" || step == "+" => Arg::Unknown(step.clone()),
                    other => (*other).clone(),
                });
            Some(target.unwrap_or_else(|| {
                // With no path, a stage after the first takes it from the
                // pipeline; the first goes home.
                if unit.stage.is_some_and(|stage| stage.index > 0) {
                    Arg::Unknown(key)
                } else {
                    Arg::Known("~".to_string())
                }
            }))
        }
        _ => None,
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

/// The most nested script text read for one line, in bytes: past it, the
/// line is unreadable. A nested script is read once for each time the line
/// starts it, so this bounds the work whatever the nesting does. It is a
/// few times the longest line, which a plain line never nears.
const MAX_NESTED_READ: usize = 4 * MAX_LEN;

/// The most here-documents a POSIX script may start on one line before it is
/// not read: the bash grammar holds each until the line ends and takes time
/// that grows with the square of how many are waiting (a second, at the
/// length limit), and no real script starts this many on a line. Here-
/// documents on lines of their own that follow a command (`cat <<A` and a
/// line break, repeated) cost no more than the text does, and here-strings
/// (`<<<`) are not here-documents. Here-documents with no command before the
/// `<<` are slow without being counted (`<<A` and a line break, repeated to
/// the length limit, takes seconds in a release build) and are listed with
/// the other slow noise in `docs/design/shell.md`.
const MAX_HEREDOCS: usize = 256;

/// The most `&`, and the most `|`, a cmd line may hold before it is not
/// read: cmd's grammar nests a chain one level for each, so a line past
/// the depth the walk goes is unreadable whatever else it holds, and its
/// grammar takes time that grows with the square of the chain to find that
/// out (seconds, at the length limit).
const MAX_CMD_SEPARATORS: usize = MAX_TREE_DEPTH;

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

/// The most functions that move the line or whose definition is redirected
/// that a line may define (a name defined again counts again, kept or
/// replaced) before the line is unknown instead of placed call by call from
/// where each function was defined: a line that defines more is not one a
/// person wrote to be read call by call, and it bounds what a call has to
/// look through.
const MAX_MOVING_FUNCTIONS: usize = 256;

/// Whether the grammar of `shell` would take too long over `text`, and why,
/// found by counting bytes without parsing:
///
/// - more `(` opened (`{` and `[` are not counted), with none closed in
///   between, than a parse tree is walked deep (the line is unreadable whatever the grammar makes of it,
///   and cmd's takes seconds to find that out at the length limit);
/// - in cmd, more `&`, or more `|`, than [`MAX_CMD_SEPARATORS`] (`&&` and
///   `||` count once);
/// - in a POSIX shell, more here-documents started on one line (a `\` before
///   the line break continues it) than [`MAX_HEREDOCS`].
///
/// The count ignores quoting, so it can only err towards unreadable.
fn too_tangled(text: &str, shell: Shell) -> Option<&'static str> {
    let bytes = text.as_bytes();
    let (mut open, mut heredocs) = (0_usize, 0_usize);
    let (mut ands, mut pipes) = (0_usize, 0_usize);
    // How many `<` in a row end just before `at`, and whether the `&` or `|`
    // just before it was the second of a pair.
    let (mut run, mut paired) = (0_usize, false);
    // A line break after the text settles a run of `<` at its end.
    for (at, byte) in bytes
        .iter()
        .copied()
        .chain(std::iter::once(b'\n'))
        .enumerate()
    {
        if byte == b'<' {
            run += 1;
            continue;
        }
        // `<<EOF` starts a here-document, `<<<` a here-string; more than
        // three in a row is noise, which counts.
        if shell == Shell::Posix && (run == 2 || run >= 4) {
            heredocs += 1;
            if heredocs > MAX_HEREDOCS {
                return Some("starts too many here-documents to read");
            }
        }
        run = 0;
        match byte {
            b'(' => {
                open += 1;
                if open > MAX_TREE_DEPTH {
                    return Some("nests too deeply to read");
                }
            }
            b')' => open = open.saturating_sub(1),
            b'\n' if at == 0 || bytes[at - 1] != b'\\' => heredocs = 0,
            b'&' | b'|' if shell == Shell::Cmd => {
                // The second of two the same is part of `&&` or `||`.
                let second = !paired && at >= 1 && bytes[at - 1] == byte;
                paired = second;
                if !second {
                    let count = if byte == b'&' { &mut ands } else { &mut pipes };
                    *count += 1;
                    if *count > MAX_CMD_SEPARATORS {
                        return Some("chains too many commands to read");
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Split `command`, started on the drive `drive` with home on `home_drive`;
/// `effect` says it is also read for [`crate::effect`].
pub(crate) fn split(
    command: &str,
    shell: Shell,
    (drive, home_drive): (Option<char>, Option<char>),
    effect: bool,
) -> Split {
    let mut split = Split {
        drive,
        home_drive,
        ..Split::default()
    };
    split.kept.on = effect;
    script(&mut split, command, shell, 0);
    if split.psdrive {
        // A drive the line makes may be entered before the text that makes
        // it (a function body, a loop), so read the line again knowing it.
        split = Split {
            psdrive: true,
            drive,
            home_drive,
            ..Split::default()
        };
        script(&mut split, command, shell, 0);
    }
    split.hide_bodies();
    split.settle_later();
    split.settle_functions();
    split.settle_pwd();
    split
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
    if depth > 0 {
        split.nested_read += text.len() + 1;
        if split.nested_read > MAX_NESTED_READ {
            split.problem(Rule::Unreadable, "starts too many scripts to read", None);
            return false;
        }
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
    if let Some(why) = too_tangled(text, shell) {
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
    split.coproc_groups = groups;
    split.apart -= usize::from(apart);
    if !here {
        split.restore_dir(outer);
    }
}

/// Parse `text` with `language`; `None` (and a finding) when the parser
/// gives nothing back, and a finding beside the tree when part of it is an
/// error.
pub(crate) fn parse(
    split: &mut Split,
    text: &str,
    language: &tree_sitter::Language,
) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let tree = parser
        .set_language(language)
        .ok()
        .and_then(|()| parser.parse(text, None));
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

/// The arguments that are not POSIX-style options: everything after `--`,
/// and what does not start with `-` before it. `takes_value` names the
/// options whose next argument is their value, not an operand.
pub(crate) fn operands<'a>(args: &'a [Arg], takes_value: &[&str]) -> Vec<&'a Arg> {
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
                    iter.next();
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

/// Whether `text` is a `/X`-style switch, not a path. A long path spelt with
/// forward slashes (`//?/C:/x`) is a path: read as one, it can only be judged
/// more strictly.
pub(crate) fn is_switch(text: &str) -> bool {
    text.starts_with('/')
        && text.len() > 1
        && !text[1..].contains(['\\', '.'])
        && milo_guards_core::spelling::verbatim(text).is_none()
}

/// The arguments that are not `/X`-style switches.
pub(crate) fn plain(args: &[Arg]) -> Vec<&Arg> {
    args.iter()
        .filter(|arg| !arg.known().is_some_and(is_switch))
        .collect()
}
