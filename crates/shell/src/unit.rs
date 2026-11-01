//! A command line split into units, one per program it runs, whichever
//! grammar split it; and the helpers that read a unit's arguments.

use std::cell::RefCell;
use std::collections::HashMap;
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
            hidden: false,
            startup: Rc::default(),
            repeated: false,
            downloaded: false,
            listings: Vec::new(),
            unread_item: false,
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

/// Everything a line was split into.
#[derive(Debug, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is a separate fact the one walk of the line latches"
)]
pub(crate) struct Split {
    pub(crate) units: Vec<Unit>,
    pub(crate) writes: Vec<Write>,
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
    /// Whether the command being added has a word with zsh's `(D)` glob
    /// qualifier, which lets that command's wildcards match a leading dot
    /// without any option on: `rm -rf *git(D)`. It belongs to the command
    /// alone, so it is not part of [`Split::dotglob`].
    qualified: bool,
    /// How deep the line is inside something that may not run, or runs in
    /// a process of its own: the right side of `&&` and `||`, a branch, a
    /// loop, a function body, a background command.
    pub(crate) branches: usize,
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

/// Where the walk was when an action that runs later began.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Began {
    units: usize,
    writes: usize,
    reads: usize,
    findings: usize,
    moved: usize,
}

/// Where the line was, to put back after a subshell or a nested script
/// whose `cd` must not reach the rest of the line.
#[derive(Debug, Clone)]
pub(crate) struct Place {
    dir: Option<Arg>,
    dir_code: bool,
    moves: usize,
    later: usize,
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
        unit.hidden = self.hidden();
        unit.repeated = self.repeats > 0;
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
        if let Some(target) = moves_to(&unit) {
            self.moves += 1;
            self.moved += 1;
            let dir = crate::path::within(self.dir.as_ref(), &target, unit.shell);
            // Once the line makes a drive, a drive letter may name it: the
            // place is only known when it runs.
            let dir = match dir {
                Arg::Known(text) if self.psdrive && crate::path::drive_of(&text).is_some() => {
                    Arg::Unknown(text)
                }
                dir => dir,
            };
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
        }
        self.units.push(unit);
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

    /// Add a redirect's write, made where the line has moved to.
    pub(crate) fn write(&mut self, shell: Shell, target: Arg) {
        let dir = self.dir.clone();
        let hidden = self.hidden();
        if self.bodies > 0 {
            self.write_in_body.push(self.writes.len());
        }
        self.writes.push(Write {
            shell,
            target,
            dir,
            hidden,
        });
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

    /// Add a redirect's read, made where the line has moved to.
    pub(crate) fn read(&mut self, shell: Shell, target: Arg) {
        let dir = self.dir.clone();
        let hidden = self.hidden();
        if self.bodies > 0 {
            self.read_in_body.push(self.reads.len());
        }
        self.reads.push(Read {
            shell,
            target,
            dir,
            hidden,
        });
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
    }

    /// Where the line has moved to, to put back after a subshell or a nested
    /// script whose `cd` must not reach the rest of the line.
    pub(crate) fn dir_snapshot(&self) -> Place {
        Place {
            dir: self.dir.clone(),
            dir_code: self.dir_code,
            moves: self.moves,
            later: self.later.len(),
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
        self.moves = place.moves;
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
                    )
                })
            })
    }

    /// Note that code is given to an interpreter that the guard does not read
    /// whole: the line is `unknown` unless it has a finding of its own.
    pub(crate) fn unread_code(&mut self, code: &str) {
        if self.unread.is_empty() {
            self.unread.push(Finding {
                rule: Rule::Unknown,
                reason: "runs code the guard does not read fully".to_string(),
                target: Some(crate::inline::shorten(code)),
            });
        }
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
        Shell::Cmd => {
            lower.len() == 1
                && lower.chars().all(|c| c.is_ascii_alphabetic())
                && unit.args.first().and_then(Arg::known) == Some(":")
        }
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
        // `pushd` alone swaps the top of the stack and `pushd +1` rotates
        // it: neither names where it goes.
        (Shell::Posix, "pushd") => match unit.args.first() {
            Some(Arg::Known(target))
                if !(target.starts_with(['+', '-'])
                    && target.len() > 1
                    && target[1..].chars().all(|c| c.is_ascii_digit())) =>
            {
                Some(Arg::Known(target.clone()))
            }
            Some(other) => Some(Arg::Unknown(other.text().to_string())),
            None => Some(Arg::Unknown(key)),
        },
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

/// Split `command`; `effect` says it is also read for [`crate::effect`].
pub(crate) fn split(command: &str, shell: Shell, effect: bool) -> Split {
    let mut split = Split::default();
    split.kept.on = effect;
    script(&mut split, command, shell, 0);
    if split.psdrive {
        // A drive the line makes may be entered before the text that makes
        // it (a function body, a loop), so read the line again knowing it.
        split = Split {
            psdrive: true,
            ..Split::default()
        };
        script(&mut split, command, shell, 0);
    }
    split.hide_bodies();
    split.settle_later();
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
    // does not move the line that started it. `eval`'s runs in this shell.
    let outer = split.dir_snapshot();
    match shell {
        Shell::Posix => crate::posix::split(split, text, depth),
        Shell::PowerShell => crate::powershell::split(split, text, depth),
        Shell::Cmd => crate::cmd::split(split, text, depth),
    }
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
