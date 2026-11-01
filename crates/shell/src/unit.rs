//! A command line split into units, one per program it runs, whichever
//! grammar split it; and the helpers that read a unit's arguments.

use crate::dotglob;
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
}

impl Arg {
    pub(crate) fn known(&self) -> Option<&str> {
        match self {
            Self::Known(text) => Some(text),
            Self::Unknown(_) | Self::Template { .. } | Self::Input => None,
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
#[derive(Debug, Clone)]
pub(crate) struct Unit {
    /// The shell whose syntax its arguments are in.
    pub(crate) shell: Shell,
    pub(crate) program: Arg,
    pub(crate) args: Vec<Arg>,
    /// The wrappers taken off in front of it, by name: `sudo`, `env`.
    pub(crate) wrappers: Vec<String>,
    pub(crate) stage: Option<Stage>,
    pub(crate) reads: Reads,
    /// Where an earlier `cd` in the line moved to, when one did: relative
    /// paths resolve from there.
    pub(crate) dir: Option<Arg>,
    /// Whether an earlier unit in the line turned on a shell option that
    /// lets a wildcard match a leading dot (`shopt -s dotglob`, `setopt
    /// globdots`, a non-empty `GLOBIGNORE`): its patterns can match `.git`.
    pub(crate) hidden: bool,
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
            dir: None,
            hidden: false,
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

/// Everything a line was split into.
#[derive(Debug, Default)]
pub(crate) struct Split {
    pub(crate) units: Vec<Unit>,
    pub(crate) writes: Vec<Write>,
    /// The files redirected from (`< file`), where the line was.
    pub(crate) reads: Vec<Read>,
    /// The `for` loops over words written out, whose variable the body does
    /// not set: a rule reads the body with each word in place.
    pub(crate) bindings: Vec<Binding>,
    /// What splitting itself found: what could not be read, scripts known
    /// only when they run.
    pub(crate) findings: Vec<Finding>,
    pipelines: usize,
    /// Where the `cd`s read so far moved to.
    dir: Option<Arg>,
    /// Variables the line sets, unsets or reads into (lower case): a path
    /// built from one of them is no longer the place its name says.
    reassigned: Vec<String>,
    /// Whether the shell reading the line has turned on a option that lets a
    /// wildcard match a leading dot, bash's or zsh's. Once on it stays on,
    /// except that a subshell or a script in a process of its own gives it
    /// back as it was, and only a certain off switch turns it off.
    dotglob: Hidden,
    /// Whether the command being added hands the option to a shell it
    /// starts, and not to itself: `GLOBIGNORE=x bash -c '…'`. The shell that
    /// expands the command's own wildcards has run them before it applies.
    scoped_dotglob: bool,
    /// How deep the line is inside something that may not run, or runs in
    /// a process of its own: the right side of `&&` and `||`, a branch, a
    /// loop, a function body, a background command.
    pub(crate) branches: usize,
    /// How deep the line is inside a function body or a loop, whose
    /// commands may run after the line has turned the option on.
    pub(crate) bodies: usize,
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
    /// What only `effect` needs of the line, kept only when it is read for
    /// `effect`, so `classify` costs what it did.
    pub(crate) kept: Kept,
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
    pub(crate) units: std::ops::Range<usize>,
    /// The redirects from a file added while it was read.
    pub(crate) reads: std::ops::Range<usize>,
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
    moves: usize,
    later: usize,
}

/// An action that runs later, in this shell, from wherever the line has
/// moved to by then (a `trap`'s script, a PowerShell event's block): the
/// units and writes it added, and how many `cd`s the line had read when it
/// ended.
#[derive(Debug)]
struct Later {
    units: std::ops::Range<usize>,
    writes: std::ops::Range<usize>,
    reads: std::ops::Range<usize>,
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
    /// Add a unit, run where the line has moved to; a `cd` moves the line.
    pub(crate) fn push(&mut self, mut unit: Unit) {
        unit.dir.clone_from(&self.dir);
        unit.hidden = self.hidden();
        if let Some(change) = unit
            .key()
            .filter(|_| unit.shell == Shell::Posix)
            .and_then(|key| dotglob::change(&key, &unit.args))
        {
            // Behind `env` or `nohup` a builtin runs in a process of its own.
            let own = dotglob::in_shell(&unit.wrappers);
            let certain = own && unit.stage.is_none();
            for (flag, on) in [(Flag::Bash, change.bash), (Flag::Zsh, change.zsh)] {
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
        if let Some(target) = moves_to(&unit) {
            self.moves += 1;
            self.moved += 1;
            self.dir = Some(crate::path::within(self.dir.as_ref(), &target, unit.shell));
        }
        self.units.push(unit);
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
        self.dotglob.any()
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
        self.moves = place.moves;
    }

    /// Record that the line sets or unsets the variable `name`, for `effect`.
    pub(crate) fn set(&mut self, name: &str) {
        if self.kept.on {
            self.kept.sets.push(name.to_string());
        }
    }

    /// Record the variable of a `for` loop, for `effect`.
    pub(crate) fn loop_variable(&mut self, name: &str) {
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
    pub(crate) fn wrapped(&mut self, effect: crate::Effect) {
        match effect {
            crate::Effect::ReadsOnly => {}
            crate::Effect::Changes => self.kept.changes |= self.kept.on,
            crate::Effect::Unknown => self.opaque(),
        }
    }

    /// Record that the line sets the variable `name`.
    pub(crate) fn reassign(&mut self, name: &str) {
        let name = name.to_ascii_lowercase();
        if !self.reassigned.contains(&name) {
            self.reassigned.push(name);
        }
    }

    /// Whether the line sets the variable `name` anywhere.
    pub(crate) fn reassigned(&self, name: &str) -> bool {
        self.reassigned
            .iter()
            .any(|known| known.eq_ignore_ascii_case(name))
    }

    /// A new pipeline's number.
    pub(crate) fn pipeline(&mut self) -> usize {
        self.pipelines += 1;
        self.pipelines
    }

    pub(crate) fn problem(&mut self, rule: Rule, reason: &str, target: Option<&str>) {
        self.findings.push(Finding {
            rule,
            reason: reason.to_string(),
            target: target.map(str::to_string),
        });
    }
}

/// Where a `cd` (`pushd`, `Set-Location`) moves to, when `unit` is one.
pub(crate) fn moves_to(unit: &Unit) -> Option<Arg> {
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
            let target = params
                .values(&["path", "literalpath"])
                .first()
                .or(params.positional.first())
                .map(|target| (*target).clone());
            Some(target.unwrap_or_else(|| Arg::Known("~".to_string())))
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
const MAX_LEN: usize = 64 * 1024;

/// The most nested script text read for one line, in bytes: past it, the
/// line is unreadable. A nested script is read once for each time the line
/// starts it, so this bounds the work whatever the nesting does. It is a
/// few times the longest line, which a plain line never nears.
const MAX_NESTED_READ: usize = 4 * MAX_LEN;

/// Split `command`; `effect` says it is also read for [`crate::effect`].
pub(crate) fn split(command: &str, shell: Shell, effect: bool) -> Split {
    let mut split = Split::default();
    split.kept.on = effect;
    script(&mut split, command, shell, 0);
    split.hide_bodies();
    split.settle_later();
    split
}

/// Split `text`, run by `shell`, `depth` shells deep, into `split`.
pub(crate) fn script(split: &mut Split, text: &str, shell: Shell, depth: usize) {
    script_in(split, text, shell, depth, false);
}

/// As [`script`]; `here` says the script runs in this shell, as `eval`'s
/// does, so what it does to the working directory stays.
pub(crate) fn script_in(split: &mut Split, text: &str, shell: Shell, depth: usize, here: bool) {
    if depth > MAX_DEPTH {
        split.problem(
            Rule::Unreadable,
            "starts shells inside shells too deeply to read",
            None,
        );
        return;
    }
    if text.len() > MAX_LEN {
        split.problem(Rule::Unreadable, "is too long to read", None);
        return;
    }
    if depth > 0 {
        split.nested_read += text.len() + 1;
        if split.nested_read > MAX_NESTED_READ {
            split.problem(Rule::Unreadable, "starts too many scripts to read", None);
            return;
        }
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

/// The arguments that are not `/X`-style switches.
pub(crate) fn plain(args: &[Arg]) -> Vec<&Arg> {
    args.iter()
        .filter(|arg| {
            !arg.known().is_some_and(|text| {
                text.starts_with('/') && text.len() > 1 && !text[1..].contains(['\\', '.'])
            })
        })
        .collect()
}
