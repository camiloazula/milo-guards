//! The rules: each reads a unit's program, flags, operands and redirects,
//! and judges every path by where it resolves.

use crate::launch::{
    after_run, find_targets, is_node, is_stdin, options, own_args, powershell_file, uv_script,
    BUN_VALUES, DENO_VALUES, INTERPRETERS, SHELLS,
};
use crate::path::{self, Access, Place, Resolver};
use crate::powershell::Params;
use milo_guards_core::spelling::glob;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::unit::{operands, plain, Arg, Importing, Reads, Scope, Split, Unit};
use crate::{Finding, Rule, Shell};
use milo_guards_core::Flavour;

mod archives;
mod code;
mod data;
mod files;
mod processes;
mod regex;
mod resources;
mod secrets;
mod send;
mod settings;
mod system;

/// Programs that run what they wrap as root or administrator.
const ELEVATORS: [&str; 8] = [
    "sudo",
    "doas",
    "su",
    "pkexec",
    "gsudo",
    "runas",
    "run0",
    "systemd-run",
];

/// Builtins that start no program: they print, test, move or set a variable,
/// so a `BASH_ENV` file is not run for them (one set in front of a special
/// builtin stays set for the rest of the line: see `startup::SPECIAL`).
pub(crate) const STARTS_NOTHING: [&str; 21] = [
    "echo", "printf", "true", "false", ":", "cd", "export", "unset", "set", "pwd", "test", "[",
    "read", "declare", "typeset", "local", "readonly", "shift", "exit", "return", "wait",
];

/// The extensions Windows runs a program by when its name has none.
const WINDOWS_EXTENSIONS: [&str; 4] = [".bat", ".cmd", ".com", ".exe"];

/// Programs that download, whose output piped into a shell is a downloaded
/// script.
pub(crate) const DOWNLOADERS: [&str; 10] = [
    "curl",
    "wget",
    "fetch",
    "http",
    "https",
    "xh",
    "aria2c",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
];

/// What the reason of a finding judged from another folder a `cd` before it
/// may have left the line in ends with (see [`Unit::others`]).
const MOVED_OFF: &str = " if a cd before it failed or did not run";

/// What the rules found in a split line: the findings of the whole line,
/// and where each came from.
#[derive(Debug, Default)]
pub(crate) struct Judged {
    /// Every finding, each once: what `classify` answers.
    pub(crate) found: Vec<Finding>,
    /// What splitting itself found: what could not be read, scripts known
    /// only when they run.
    pub(crate) line: Vec<Finding>,
    /// What each unit produced, in the order of `Split::units`.
    pub(crate) units: Vec<Vec<Finding>>,
    /// What each redirect's write produced, in the order of `Split::writes`.
    pub(crate) writes: Vec<Vec<Finding>>,
}

pub(crate) fn findings(split: &Split, resolver: &Resolver) -> Judged {
    let mut checker = Checker::new(split, resolver);
    checker.found.clone_from(&split.findings);
    for unit in &split.units {
        let by_cmdlet = writes_by_cmdlet(unit);
        for target in written_by(unit) {
            checker.written(unit.dir.as_ref(), &target, unit.shell);
            // Written where a `cd` that may not have run may have left the
            // line, as for a redirect (see [`Split::unsure_writes`]).
            if !unit.elsewhere.is_empty() {
                checker.written_anywhere(&target, unit.shell);
            }
            // A file a write cmdlet names only when it runs (`$x` in `Set-Content
            // a.txt,$x y`, which is not told from the value of `Set-Content a.txt
            // $x`) may be any file: a script the line runs may be it.
            if by_cmdlet && matches!(target, Arg::Unknown(_) | Arg::Template { .. }) {
                checker.anywhere = true;
            }
        }
    }
    // A write placed from another folder the line may be in is read for a
    // later run from that folder already (see [`Unit::others`]).
    for write in split.writes.iter().filter(|write| !write.also) {
        checker.written(write.dir.as_ref(), &write.target, write.shell);
    }
    for write in &split.unsure_writes {
        checker.written_anywhere(&write.target, write.shell);
    }
    checker.flow = checker.trace();
    // What each step adds to `found` is what that step found: the findings
    // from `split.findings` come first, and are the line's own.
    let mut line = checker.found.clone();
    let mut units = Vec::with_capacity(split.units.len());
    for (at, unit) in split.units.iter().enumerate() {
        let before = checker.found.len();
        checker.unit(at, unit, true);
        // A `cd` before it that may not have run, or may have failed, may
        // have left the line in another folder: its paths are judged from
        // there too. A run of a file the line wrote is judged from each of
        // them already.
        let own = checker.found.len();
        for dir in unit.others() {
            checker.unit(at, &unit.in_folder(dir), false);
        }
        checker.moved_off(before, own);
        checker.loose(at, before);
        units.push(checker.found[before..].to_vec());
    }
    // A read through `<` is not a unit's: it belongs to the line.
    let before = checker.found.len();
    checker.redirected_reads();
    line.extend_from_slice(&checker.found[before..]);
    let mut writes: Vec<Vec<Finding>> = Vec::with_capacity(split.writes.len());
    // A redirect is written from each folder the line may be in, and a
    // folder a `cd` that may have failed left the line in stays one of them
    // for the units after it: the same file from the same folder is judged
    // once.
    type Key<'s> = (Shell, Option<&'s Arg>, bool, &'s Arg, bool);
    let mut judged: HashMap<Key<'_>, Vec<Finding>> = HashMap::new();
    // What the redirect being read found from the folders the walk has the
    // line in (the writes of one redirect come together, those first): from
    // another folder the line may be in, the same finding is that one.
    let mut plain: (Option<&Arg>, Vec<Finding>) = (None, Vec::new());
    for write in &split.writes {
        if !write.also && plain.0 != Some(&write.target) {
            plain = (Some(&write.target), Vec::new());
        }
        let key = (
            write.shell,
            write.dir.as_ref(),
            write.hidden,
            &write.target,
            write.also,
        );
        let found = if let Some(found) = judged.get(&key) {
            checker.found.extend_from_slice(found);
            found.clone()
        } else {
            let before = checker.found.len();
            checker.write(write.shell, write.scope(), &write.target, "writes to");
            if write.also {
                let mine = std::mem::take(&mut plain.1);
                checker.moved_off_from(&mine, before);
                plain.1 = mine;
            }
            let found = checker.found[before..].to_vec();
            judged.insert(key, found.clone());
            found
        };
        if !write.also {
            plain.1.extend_from_slice(&found);
        }
        writes.push(found);
    }
    // Inline code the guard did not read whole is `unknown`, but only where
    // nothing else was found: a line that already asks, or that the guard is
    // certain of (a delete, a write, a key), says so.
    if checker.found.is_empty() {
        let mut unread = split.unread.clone();
        // Code that imports is read whole only where Python looks first for
        // what it imports: the workspace's own folders.
        if unread.is_empty() {
            unread.extend(
                split
                    .importing
                    .iter()
                    .find(|code| !checker.imports_in_workspace(code))
                    .map(|code| code.finding.clone()),
            );
        }
        line.extend_from_slice(&unread);
        checker.found.extend_from_slice(&unread);
    }
    let mut seen = HashSet::new();
    checker.found.retain(|finding| seen.insert(finding.clone()));
    Judged {
        found: checker.found,
        line,
        units,
        writes,
    }
}

/// The most distinct patterns the line is read for: each script the line
/// runs is matched against every one of them (and PowerShell tries a name
/// with each of the executable extensions), so the work of a line grows with
/// the patterns it writes by and the scripts it runs. Past this many, the
/// line is read as writing any file.
const MAX_PATTERNS: usize = 8;

/// The longest file name part of a pattern the line is read for: matching
/// costs the length of the pattern times the length of the name. A longer one
/// is read as writing any file.
const MAX_PATTERN_LEN: usize = 64;

/// The longest name of a script that is matched against the patterns, for
/// the same reason. No file has a longer one, but the guard does not rely on
/// that: a run of one is read as of a file the pattern may match.
const MAX_NAME_LEN: usize = 255;

/// A pattern the line writes by (`Set-Content *.ps1 x`): every file it
/// matches is written.
#[derive(PartialEq)]
struct WrittenPattern {
    /// The key of the folder it is in; `None` when that cannot be placed.
    folder: Option<String>,
    /// The file name part, which holds the wildcard.
    name: String,
    /// The shell that wrote it, which says how it is read.
    shell: Shell,
}

/// `path` as the folder it is in (the working folder, `.`, when it has no
/// separator) and its file name.
fn split_name(path: &str, shell: Shell) -> (String, &str) {
    match path.rsplit_once(separators(shell)) {
        Some(("", name)) => ("/".to_string(), name),
        Some((folder, name)) => (folder.to_string(), name),
        None => (".".to_string(), path),
    }
}

struct Checker<'a> {
    split: &'a Split,
    resolver: &'a Resolver,
    found: Vec<Finding>,
    /// Every file the line writes, by [`Resolver::file_key`]: redirects,
    /// downloads, copies, `tee`, `dd`.
    written: HashSet<String>,
    /// Whether the line writes a file it cannot place (a target known only
    /// when it runs, or after a `cd` to such a place): it has no key, but
    /// may be a script the line runs.
    unplaced_write: bool,
    /// The file name part of each pattern the line writes by (`*.ps1`), with
    /// the shell that wrote it: every file it matches is written.
    patterns: Vec<WrittenPattern>,
    /// The file name of each file the line writes where it may be in more
    /// than one folder (see [`Split::unsure_writes`]), in lower case: when a
    /// `cd` before it did not run, the file is in a folder the walk may no
    /// longer have, so a script of that name, in any folder, may be it.
    unsure_names: HashSet<String>,
    /// Whether the line writes a file that is any file: a name a write
    /// cmdlet takes only when it runs, or more patterns, or longer ones,
    /// than are read ([`MAX_PATTERNS`]). Any script the line runs may be it.
    anywhere: bool,
    /// For each pipeline, the first stage that downloads.
    downloaders: HashMap<usize, usize>,
    /// The first unit at each pipeline stage, by its index in the split.
    producers: HashMap<(usize, usize), usize>,
    /// Every unit at each pipeline stage, by its index in the split: a stage
    /// can be a group of several.
    stages: HashMap<(usize, usize), Vec<usize>>,
    /// Whether the line lists keys in Redis, once worked out: every
    /// `redis-cli del` that is given keys asks, and the answer is the line's.
    scans_keys: Option<bool>,
    /// What the line says to its database clients, read once for each stage.
    data: data::Cache,
    /// The number of stages of each pipeline.
    lengths: HashMap<usize, usize>,
    /// The `Get-Process` that starts a pipeline, read when a `Stop-Process`
    /// first asks for it.
    pipelines: HashMap<usize, Option<std::rc::Rc<processes::Pipeline>>>,
    /// Where secrets are read and where they go, for the rule that finds
    /// them sent away.
    flow: send::Flow,
}

impl<'a> Checker<'a> {
    /// A checker of `split` that has found nothing yet, with the stages of
    /// its pipelines indexed once, so each unit's pipeline questions are
    /// lookups, not scans of every unit.
    fn new(split: &'a Split, resolver: &'a Resolver) -> Self {
        let mut checker = Checker {
            split,
            resolver,
            found: Vec::new(),
            written: HashSet::new(),
            unplaced_write: false,
            patterns: Vec::new(),
            unsure_names: HashSet::new(),
            anywhere: false,
            downloaders: HashMap::new(),
            producers: HashMap::new(),
            stages: HashMap::new(),
            scans_keys: None,
            data: data::Cache::default(),
            lengths: HashMap::new(),
            pipelines: HashMap::new(),
            flow: send::Flow::default(),
        };
        for (at, unit) in split.units.iter().enumerate() {
            let Some(stage) = unit.stage else {
                continue;
            };
            if unit
                .key()
                .is_some_and(|key| DOWNLOADERS.contains(&key.as_str()))
            {
                checker
                    .downloaders
                    .entry(stage.pipeline)
                    .and_modify(|first| *first = (*first).min(stage.index))
                    .or_insert(stage.index);
            }
            checker
                .producers
                .entry((stage.pipeline, stage.index))
                .or_insert(at);
            checker
                .stages
                .entry((stage.pipeline, stage.index))
                .or_default()
                .push(at);
            let length = checker.lengths.entry(stage.pipeline).or_insert(0);
            *length = (*length).max(stage.index + 1);
        }
        checker
    }
}

impl Checker<'_> {
    /// Whether inline Python that imports runs in a workspace folder: where
    /// the folder the line had moved to is, or the working directory when it
    /// had not. A code in a function body or a loop runs again after any
    /// `cd` of the line, so the folder is not known when the line has one.
    fn imports_in_workspace(&self, code: &Importing) -> bool {
        let moved = Arg::Unknown("where the line moves to".to_string());
        let dir = if code.repeated && self.split.ever_moves() {
            Some(&moved)
        } else {
            code.dir.as_ref()
        };
        matches!(
            self.resolver.place(
                dir,
                &Arg::Known(".".to_string()),
                Shell::Posix,
                false,
                Access::Item
            ),
            Place::Inside | Place::Workspace { exact: true }
        )
    }

    /// Note a file the line writes, from `dir`.
    fn written(&mut self, dir: Option<&Arg>, target: &Arg, shell: Shell) {
        if let Some(key) = self.resolver.file_key(dir, target, shell) {
            self.written.insert(key);
        } else if self.resolver.unplaced(dir, target, shell) {
            self.unplaced_write = true;
        } else if let Arg::Known(text) = target {
            // A pattern writes every file it matches: a script of that
            // name is one the line may write.
            if glob::has_wildcard(text) {
                let (folder, name) = split_name(text, shell);
                // A folder that cannot be placed (a pattern in it too) is
                // any folder.
                let folder = self.resolver.file_key(dir, &Arg::Known(folder), shell);
                self.add_pattern(WrittenPattern {
                    folder,
                    name: name.to_string(),
                    shell,
                });
            }
        }
    }

    /// Note a file the line writes from a folder it may not have when a
    /// later run is read (see [`Split::unsure_writes`]): a script of that
    /// name, in any folder, may be it.
    fn written_anywhere(&mut self, target: &Arg, shell: Shell) {
        let Arg::Known(text) = target else {
            return;
        };
        let (_, name) = split_name(text, shell);
        if name.is_empty() {
            return;
        }
        if glob::has_wildcard(name) {
            self.add_pattern(WrittenPattern {
                folder: None,
                name: name.to_string(),
                shell,
            });
        } else {
            self.unsure_names.insert(name.to_lowercase());
        }
    }

    /// Note a pattern the line writes by: the same pattern again adds
    /// nothing; too many, or one too long to match cheaply, is any file.
    fn add_pattern(&mut self, pattern: WrittenPattern) {
        if pattern.name.len() > MAX_PATTERN_LEN {
            self.anywhere = true;
        } else if !self.patterns.contains(&pattern) {
            if self.patterns.len() < MAX_PATTERNS {
                self.patterns.push(pattern);
            } else {
                self.anywhere = true;
            }
        }
    }

    /// Whether the line may write the file `script` names from `dir`, other
    /// than by a name it can read: it writes any file (see
    /// [`Self::anywhere`]), a file of its name from a folder it may not have
    /// (see [`Self::unsure_names`]), or by a pattern whose folder is the
    /// script's and whose name matches its name. Each call costs a bounded amount: at most
    /// [`MAX_PATTERNS`] matches of at most [`MAX_PATTERN_LEN`] bytes against
    /// a name of at most [`MAX_NAME_LEN`].
    fn pattern_written(&self, dir: Option<&Arg>, script: &str, shell: Shell) -> bool {
        if self.anywhere {
            return true;
        }
        let (folder, name) = split_name(script, shell);
        if self.unsure_names.contains(&name.to_lowercase()) {
            return true;
        }
        if self.patterns.is_empty() {
            return false;
        }
        if name.len() > MAX_NAME_LEN {
            return true;
        }
        let folder = self.resolver.file_key(dir, &Arg::Known(folder), shell);
        self.patterns.iter().any(|pattern| {
            let flavour = if pattern.shell == Shell::Posix {
                Flavour::Posix
            } else {
                Flavour::Windows
            };
            (pattern.folder.is_none() || folder.is_none() || pattern.folder == folder)
                && glob::matches(&pattern.name, name, flavour, true)
        })
    }

    fn add(&mut self, rule: Rule, reason: impl Into<String>, target: Option<&Arg>) {
        self.found.push(Finding {
            rule,
            reason: reason.into(),
            target: target.map(|arg| arg.text().to_string()),
        });
    }

    /// The unit at `at` reads a file the code names without the guard
    /// knowing the whole path (see [`Split::loose`]): it is `unknown`, unless
    /// the unit found a key in the part that is known, from `before` on.
    fn loose(&mut self, at: usize, before: usize) {
        let Some(finding) = self.split.loose.get(&at) else {
            return;
        };
        if !self.found[before..]
            .iter()
            .any(|found| found.rule == Rule::ReadSecret)
        {
            self.found.push(finding.clone());
        }
    }

    /// The findings from `own` on were judged from another folder a `cd`
    /// before the unit may have left the line in (see [`Unit::others`]): one
    /// the unit made from where the walk has the line (from `before`) is
    /// that one, and any other says where it comes from, so a caller sees
    /// what to change (`&&` after the `cd`, or `|| exit`).
    fn moved_off(&mut self, before: usize, own: usize) {
        let mine = self.found[before..own].to_vec();
        self.moved_off_from(&mine, own);
    }

    /// As [`Self::moved_off`], with what was found from where the walk has
    /// the line given as `mine`.
    fn moved_off_from(&mut self, mine: &[Finding], own: usize) {
        let others = self.found.split_off(own);
        for mut finding in others {
            if mine.contains(&finding) {
                continue;
            }
            finding.reason.push_str(MOVED_OFF);
            if !self.found[own..].contains(&finding) {
                self.found.push(finding);
            }
        }
    }

    /// Judge `unit`, the one at `at`; `runs` says whether to judge a run of
    /// a file the line wrote too, which a copy of it in another folder the
    /// line may be in leaves to the unit itself (see [`Unit::others`]).
    fn unit(&mut self, at: usize, unit: &Unit, runs: bool) {
        self.called(unit);
        let Some(key) = unit.key() else {
            // A program only known when it runs may be a shell, or start one.
            if runs {
                self.startup_then_run(unit, None);
            }
            return;
        };
        self.elevated(unit, &key);
        self.reads(unit, unit.reads);
        self.secrets(at, unit, &key);
        if runs {
            self.write_then_run(unit, &key);
            self.program_then_run(unit);
            self.startup_then_run(unit, Some(&key));
        }
        self.files(unit, &key);
        self.send(at, unit, &key);
        self.data(at, unit, &key);
        self.resources(unit, &key);
        self.system(unit, &key);
        self.settings(at, unit, &key);
        self.code(unit, &key);
    }

    fn elevated(&mut self, unit: &Unit, key: &str) {
        let elevator = unit
            .wrappers
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(key))
            .find(|name| ELEVATORS.contains(name));
        if let Some(elevator) = elevator {
            let administrator = unit.shell != Shell::Posix || matches!(elevator, "runas" | "gsudo");
            let reason = if administrator {
                "runs as administrator"
            } else {
                "runs as root"
            };
            self.add(
                Rule::Elevated,
                reason,
                Some(&Arg::Known(elevator.to_string())),
            );
        }
    }

    /// A shell or an interpreter reading what to run from its input: a
    /// download piped into it is a downloaded script.
    fn reads(&mut self, unit: &Unit, reads: Reads) {
        let downloaded = unit.stage.is_some_and(|stage| {
            self.downloaders
                .get(&stage.pipeline)
                .is_some_and(|&first| first < stage.index)
        });
        match (reads, downloaded) {
            (Reads::Shell | Reads::Interpreter, true) => {
                self.add(Rule::RunDownloaded, "runs a downloaded script", None);
            }
            (Reads::Shell, false) => {
                self.add(Rule::RunInput, "runs commands read from its input", None);
            }
            (Reads::Interpreter, false) => {
                self.add(Rule::Unknown, "runs code the guard does not read", None);
            }
            (Reads::Nothing, _) => {}
        }
    }

    /// The places `arg` stands for: a pipeline's input is the files the
    /// stage before it lists, when that stage lists files the guard can place.
    /// Also whether the stage that listed them had wildcards match hidden
    /// names. When the stage's first unit lists, so does each other listing
    /// at that stage: a second reading of it (`ls -d .gi#t` as zsh reads it
    /// with `extendedglob` on) or another listing in its group.
    fn expand(&self, unit: &Unit, arg: &Arg) -> (Vec<Arg>, bool) {
        if *arg != Arg::Input {
            return (vec![arg.clone()], false);
        }
        let stage = unit
            .stage
            .filter(|stage| stage.index > 0)
            .map(|stage| (stage.pipeline, stage.index - 1));
        let producer = stage
            .and_then(|stage| self.producers.get(&stage))
            .and_then(|&at| self.split.units.get(at));
        let mut hidden = producer.is_some_and(|producer| producer.hidden || lists_hidden(producer));
        let Some(mut found) = producer.and_then(listed) else {
            return (vec![Arg::Unknown("<input>".to_string())], hidden);
        };
        let others = stage
            .and_then(|stage| self.stages.get(&stage))
            .into_iter()
            .flatten()
            .skip(1)
            .filter_map(|&at| self.split.units.get(at));
        for other in others {
            if let Some(more) = listed(other) {
                found.extend(more);
                hidden |= other.hidden || lists_hidden(other);
            }
        }
        (found, hidden)
    }

    fn delete(&mut self, unit: &Unit, targets: &[&Arg], verb: &str) {
        self.delete_matching(unit, targets, verb, false);
    }

    /// [`Checker::delete`], where `hidden` says the program matches the
    /// wildcards itself, with names that start with a dot among them.
    fn delete_matching(&mut self, unit: &Unit, targets: &[&Arg], verb: &str, hidden: bool) {
        for target in targets {
            let (found, listed_hidden) = self.expand(unit, target);
            let scope = Scope {
                hidden: unit.hidden || listed_hidden || hidden,
                ..unit.scope()
            };
            for arg in found {
                match self.place(unit.shell, scope, &arg, Access::Item) {
                    place if place.harmless() => {}
                    Place::Registry => {
                        self.add(Rule::SystemSettings, "changes the registry", Some(&arg));
                    }
                    Place::Disk => self.add(Rule::WipeDisk, format!("{verb} a disk"), Some(&arg)),
                    place => self.add(
                        Rule::Delete,
                        format!("{verb} {}", place.words()),
                        Some(&arg),
                    ),
                }
            }
        }
    }

    /// Sources a move takes away: anything beyond the workspace and its
    /// temporary files is lost where it was (`mv ~/x /tmp` and then
    /// `rm -rf /tmp/x` deletes it). A registry key moved is a registry
    /// change.
    fn move_away(&mut self, unit: &Unit, sources: &[&Arg], verb: &str) {
        for source in sources {
            let place = self.place(unit.shell, unit.scope(), source, Access::Item);
            match place {
                place if place.harmless() => {}
                Place::Registry => {
                    self.add(Rule::SystemSettings, "changes the registry", Some(source));
                }
                place => self.add(
                    Rule::Delete,
                    format!("{verb} {}", place.words()),
                    Some(source),
                ),
            }
        }
    }

    /// The items a PowerShell item cmdlet works on: its `-Path` or
    /// `-LiteralPath`, else its first positional argument, else what the
    /// stage before it lists; `$_` in a `ForEach-Object` block is that too.
    /// A listing that takes in the whole workspace hands on what is inside
    /// it, so those are not the workspace itself.
    fn items(&self, unit: &Unit, params: &Params<'_>) -> Vec<Arg> {
        let mut paths = params.values(&["path", "literalpath"]);
        if paths.is_empty() {
            paths.extend(params.positional.first().copied());
        }
        self.listed_paths(unit, paths)
    }

    /// The items a PowerShell item cmdlet that takes a list of paths acts on
    /// (`Clear-Item`, `Set-Item`): every `-Path` and
    /// `-LiteralPath` value and every positional, as `Remove-Item` reads
    /// them; with none, what the stage before it lists (or `$_` in a
    /// `ForEach-Object` block). A positional may be the
    /// rest of a list (`-Path a,b`, `a, b`) or an item that a parameter the
    /// guard reads as a switch (`-n`) or `--` pushed out of the first place,
    /// so each is judged; a value or a new name that is a place of its own
    /// (`Set-Item src\a HKLM:\x`) makes the cmdlet fail,
    /// so judging it costs only commands that do nothing.
    fn list_items(&self, unit: &Unit, params: &Params<'_>) -> Vec<Arg> {
        let mut paths = params.values(&["path", "literalpath"]);
        paths.extend(params.positional.iter().copied());
        self.listed_paths(unit, paths)
    }

    fn listed_paths(&self, unit: &Unit, paths: Vec<&Arg>) -> Vec<Arg> {
        if paths.is_empty() && unit.stage.is_some_and(|stage| stage.index > 0) {
            return self.listed_items(unit, &Arg::Input);
        }
        paths
            .into_iter()
            .flat_map(|arg| self.listed_items(unit, arg))
            .collect()
    }

    /// `arg`, or the places the stage before lists when it is the pipeline's
    /// input. A listing (`Get-ChildItem`, `ls`, `dir`) of the whole workspace
    /// hands on what is inside it, so that place is dropped, unless the
    /// listing is `-Force` or `-Hidden`, which hands on the hidden files too
    /// (`.git`): they are kept as the hidden files of the workspace. `Get-Item`
    /// hands on the item itself, so only a pattern of its (`Get-Item *`) is
    /// dropped and a workspace root named as written is kept.
    fn listed_items(&self, unit: &Unit, arg: &Arg) -> Vec<Arg> {
        if *arg != Arg::Input {
            return vec![arg.clone()];
        }
        let (found, hidden) = self.expand(unit, arg);
        let scope = Scope {
            hidden: unit.hidden || hidden,
            ..unit.scope()
        };
        let item = unit
            .stage
            .filter(|stage| stage.index > 0)
            .and_then(|stage| self.producers.get(&(stage.pipeline, stage.index - 1)))
            .and_then(|&at| self.split.units.get(at))
            .and_then(Unit::key)
            .is_some_and(|key| key.as_str() == "get-item");
        found
            .into_iter()
            .filter_map(|arg| {
                let named = item && !matches!(&arg, Arg::Known(text) if glob::has_wildcard(text));
                if named
                    || !matches!(
                        self.place(unit.shell, scope, &arg, Access::Item),
                        Place::Workspace { exact: true }
                    )
                {
                    Some(arg)
                } else if hidden {
                    Some(hidden_files_of(arg))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Where `arg` lands, run from `dir` where a `cd` moved.
    fn place(&self, shell: Shell, scope: Scope<'_>, arg: &Arg, access: Access) -> Place {
        self.resolver
            .place(scope.dir, arg, shell, scope.hidden, access)
    }

    /// As [`place`](Self::place), for a path something is written into.
    fn place_into(&self, shell: Shell, scope: Scope<'_>, arg: &Arg, access: Access) -> Place {
        self.resolver
            .place_into(scope.dir, arg, shell, scope.hidden, access)
    }

    /// The words of a file a tool runs on its own that a write to `arg` is,
    /// run from `dir` where a `cd` moved; with `below`, one that a recursive
    /// copy to it can replace.
    fn startup(
        &self,
        shell: Shell,
        scope: Scope<'_>,
        arg: &Arg,
        below: bool,
    ) -> Option<&'static str> {
        self.resolver.startup(
            &path::within(scope.dir, arg, shell),
            shell,
            scope.hidden,
            below,
        )
    }

    /// A folder made at `target`: as a write, except that an empty folder is
    /// no code, so one on the list of what a tool runs on its own is not a
    /// finding (`mkdir -p .github/workflows`); what is written into it is.
    fn make_folder(&mut self, shell: Shell, scope: Scope<'_>, target: &Arg, access: Access) {
        if self.startup(shell, scope, target, false).is_none() {
            self.write_as(shell, scope, target, "creates", access);
        }
    }

    fn write(&mut self, shell: Shell, scope: Scope<'_>, target: &Arg, verb: &str) {
        self.write_as(shell, scope, target, verb, Access::Content);
    }

    /// A write into a folder, as an archive unpacked into it makes.
    fn write_folder(&mut self, shell: Shell, scope: Scope<'_>, target: &Arg, verb: &str) {
        self.write_to(shell, scope, target, verb, "a folder", Access::Content);
    }

    /// A write of `target`, by how it reaches it (see [`Access`]).
    fn write_as(
        &mut self,
        shell: Shell,
        scope: Scope<'_>,
        target: &Arg,
        verb: &str,
        access: Access,
    ) {
        self.write_to(shell, scope, target, verb, "a file", access);
    }

    /// A write to `target`, which is a `what` in the words of a reason, by
    /// how it reaches it (see [`Access`]).
    fn write_to(
        &mut self,
        shell: Shell,
        scope: Scope<'_>,
        target: &Arg,
        verb: &str,
        what: &str,
        access: Access,
    ) {
        self.selinux_file(shell, scope.dir, target);
        match self.place_into(shell, scope, target, access) {
            place if place.harmless() => {}
            Place::Workspace { exact: true } | Place::Temp { exact: true } => {}
            Place::Disk => self.add(Rule::WipeDisk, "writes over a disk", Some(target)),
            Place::Registry => self.add(Rule::SystemSettings, "changes the registry", Some(target)),
            Place::Outside => self.add(
                Rule::Overwrite,
                format!("{verb} {what} outside the workspace"),
                Some(target),
            ),
            Place::Unknown => self.add(
                Rule::Overwrite,
                format!("{verb} {what} only known when it runs"),
                Some(target),
            ),
            place => self.add(
                Rule::Overwrite,
                format!("{verb} {}", place.words()),
                Some(target),
            ),
        }
    }

    /// A copy, move or link of files named `leaves` to `destination`. The
    /// destination is a file or a folder the files go into, and a line cannot
    /// say which, so both are read: it is written as a file, and each file
    /// lands at its own name in it, which is judged as the path it replaces
    /// (a wildcard name is a pattern). A recursive copy can replace anything
    /// below the folder it copies into, so there a folder that holds a
    /// protected path is not safe to copy into.
    fn copy_to(
        &mut self,
        shell: Shell,
        scope: Scope<'_>,
        leaves: &[String],
        destination: &Arg,
        recursive: bool,
    ) {
        let mut seen = HashSet::new();
        let distinct: Vec<&str> = leaves
            .iter()
            .map(String::as_str)
            .filter(|leaf| seen.insert(*leaf))
            .collect();
        self.copy_into(
            shell,
            scope,
            (&distinct, leaves.len() > 1),
            destination,
            recursive,
        );
    }

    /// As [`copy_to`](Self::copy_to), with the names of the files each once,
    /// and whether there are several files (a name given twice is two).
    pub(super) fn copy_into(
        &mut self,
        shell: Shell,
        scope: Scope<'_>,
        (leaves, several): (&[&str], bool),
        destination: &Arg,
        recursive: bool,
    ) {
        let protected = |place: Place| match place {
            Place::Protected(words) => Some(words),
            _ => None,
        };
        let words = recursive
            .then(|| protected(self.place(shell, scope, destination, Access::Item)))
            .flatten();
        match words {
            Some(words) => {
                self.add_once(Rule::Overwrite, format!("writes to {words}"), destination);
            }
            None => self.write_as(shell, scope, destination, "writes to", Access::Item),
        }
        // A recursive copy can replace anything below a folder that holds a
        // file a tool runs on its own (`cp -r x .github`).
        if recursive {
            if let Some(words) = self.startup(shell, scope, destination, true) {
                self.add_once(Rule::Overwrite, format!("writes to {words}"), destination);
            }
        }
        let Some(text) = destination.known() else {
            return;
        };
        let separators = if shell == Shell::Posix {
            &['/'][..]
        } else {
            &['/', '\\'][..]
        };
        let folder = text.trim_end_matches(separators);
        // Several sources, a trailing separator, `.` and `..` can only be a
        // folder (`-t` is made one by `sources_and_destination`).
        let folder_for_sure = several
            || text.ends_with(separators)
            || matches!(text.rsplit(separators).next(), Some("." | ".."));
        for &leaf in leaves {
            let landing = Arg::Known(format!("{folder}/{leaf}"));
            let place = if recursive {
                self.place(shell, scope, &landing, Access::Item)
            } else {
                self.place_into(shell, scope, &landing, Access::Item)
            };
            if let Some(words) = protected(place) {
                self.add_once(Rule::Overwrite, format!("writes to {words}"), destination);
            }
            // The file lands at its own name, which can be one a tool runs
            // on its own (`cp lefthook.yml sub/`). A destination that may be
            // a file as well as a folder (`cp .envrc .envrc.bak`) is not read
            // as a folder here, nor is a source that is a pattern read as a
            // name: only a destination that is a folder for certain is.
            let started = self
                .startup(shell, scope, &landing, recursive)
                .filter(|_| folder_for_sure && !glob::has_wildcard(leaf));
            if let Some(words) = started {
                self.add_once(Rule::Overwrite, format!("writes to {words}"), destination);
            }
        }
    }

    /// As [`add`](Self::add), unless the same finding is already there.
    fn add_once(&mut self, rule: Rule, reason: String, target: &Arg) {
        let target_text = target.text().to_string();
        let seen = self.found.iter().any(|found| {
            found.rule == rule
                && found.reason == reason
                && found.target.as_deref() == Some(target_text.as_str())
        });
        if !seen {
            self.add(rule, reason, Some(target));
        }
    }

    fn permissions(&mut self, unit: &Unit, targets: &[&Arg], verb: &str) {
        for target in targets {
            match self.place(unit.shell, unit.scope(), target, Access::Item) {
                place if place.harmless() => {}
                Place::Workspace { exact: true } => {}
                Place::Registry => {
                    self.add(Rule::SystemSettings, "changes the registry", Some(target));
                }
                place => self.add(
                    Rule::Permissions,
                    format!("{verb} {}", place.words()),
                    Some(target),
                ),
            }
        }
    }

    /// A shell or interpreter that runs a script the same line writes, so
    /// what it does is not in the line. PowerShell runs a file by `-File`
    /// (`pwsh`, a first word that is not a parameter, too) and
    /// `Invoke-Command -FilePath`, and a name with no extension may be the
    /// `.ps1` it tries first.
    fn write_then_run(&mut self, unit: &Unit, key: &str) {
        let file = match key {
            "powershell" | "pwsh" => powershell_file(&unit.args),
            "invoke-command" if unit.shell == Shell::PowerShell => Params::read(&unit.args)
                .values(&["filepath"])
                .first()
                .map(|file| (*file).clone()),
            _ => None,
        };
        if let Some(file) = file {
            let before = self.found.len();
            self.runs_written(unit, &file, unit.dir.as_ref());
            if self.found.len() == before {
                self.extension_then_run(unit, &file);
            }
            return;
        }
        let runner = SHELLS.contains(&key)
            || INTERPRETERS.contains(&key)
            || key == "uv"
            || key.starts_with("python3.")
            || (unit.shell == Shell::Posix && matches!(key, "source" | "."));
        if !runner {
            return;
        }
        // `node -r ./s.js main.js`: a module loaded before the script runs as
        // the script does.
        for module in preloaded(key, &unit.args) {
            self.runs_written(unit, &module, unit.dir.as_ref());
        }
        let Some(script) = script_operand(key, &unit.args) else {
            return;
        };
        self.runs_written(unit, script, unit.dir.as_ref());
    }

    /// A program started by a path (`./x.sh`, `x/run`, `/tmp/x`) is that
    /// file run as the program, as `sh x.sh` runs it, so it is checked
    /// against the files the line writes the same way. A bare name is looked
    /// up in `PATH`, not in the folder, so it is not a file the line wrote;
    /// cmd looks in the working folder first, so a bare name there is the
    /// file when the line writes one of that name (not judged when it cannot
    /// be placed: `dir` and `echo` are programs of cmd, not files). For a
    /// Windows shell a name with no extension may be the file with one of
    /// the executable extensions (`a` runs `a.bat`), and PowerShell also
    /// tries `a.ps1` first.
    fn program_then_run(&mut self, unit: &Unit) {
        let Some(program) = unit.program.known() else {
            return;
        };
        let by_path = program.contains(separators(unit.shell));
        if !by_path && unit.shell != Shell::Cmd {
            return;
        }
        if by_path {
            let before = self.found.len();
            self.runs_written(unit, &unit.program, unit.dir.as_ref());
            if self.found.len() != before {
                return;
            }
        } else if self.names_written(unit, program) {
            self.add_run_written(&unit.program);
            return;
        }
        self.extension_then_run(unit, &unit.program);
    }

    /// `script`, a name with no extension, run on a Windows shell: it may be
    /// the file the line writes with one of the executable extensions, and
    /// PowerShell tries `.ps1` first.
    fn extension_then_run(&mut self, unit: &Unit, script: &Arg) {
        let Some(name) = script.known() else {
            return;
        };
        let last = name.rsplit(separators(unit.shell)).next().unwrap_or(name);
        if unit.shell == Shell::Posix || last.contains('.') {
            return;
        }
        let first = (unit.shell == Shell::PowerShell).then_some(".ps1");
        if first
            .into_iter()
            .chain(WINDOWS_EXTENSIONS)
            .any(|extension| self.names_written(unit, &format!("{name}{extension}")))
        {
            self.add_run_written(script);
        }
    }

    /// Whether the line writes the file `name` names from where `unit` runs,
    /// or from any other folder the line may be in then (see
    /// [`Unit::elsewhere`] and [`Unit::stayed`]).
    fn names_written(&self, unit: &Unit, name: &str) -> bool {
        std::iter::once(unit.dir.as_ref())
            .chain(unit.elsewhere.iter().map(Option::as_ref))
            .chain(unit.stayed.iter().map(Option::as_ref))
            .any(|dir| {
                self.pattern_written(dir, name, unit.shell)
                    || self
                        .resolver
                        .file_key(dir, &Arg::Known(name.to_string()), unit.shell)
                        .is_some_and(|wanted| self.written.contains(&wanted))
            })
    }

    fn add_run_written(&mut self, script: &Arg) {
        self.add(
            Rule::Unknown,
            "runs a script the same line writes",
            Some(script),
        );
    }

    /// A program that starts a bash runs the file `BASH_ENV` names before
    /// that bash's own script, when the same line writes it: a shell, and
    /// any program that may start one (`make` runs its recipes with the
    /// `SHELL` of its makefile, a script with a `#!/bin/bash` line, `git`
    /// its hooks). What starts nothing is a builtin that only prints, tests
    /// or sets a variable ([`STARTS_NOTHING`]); `key` is `None` for a
    /// program only known when it runs.
    fn startup_then_run(&mut self, unit: &Unit, key: Option<&str>) {
        if unit.shell != Shell::Posix || key.is_some_and(|key| STARTS_NOTHING.contains(&key)) {
            return;
        }
        // The files the line sets for every shell it starts count wherever
        // the unit sits, as the files it writes do: an assignment is read
        // where it is written, and a trap action, the next pass of a loop or
        // a function body runs after it.
        for entry in unit.startup.iter().chain(self.split.startup.iter()) {
            // `BASH_ENV=/dev/stdin` is the shell's input run as a script, as
            // `bash /dev/stdin` is.
            if entry.file.known().is_some_and(is_stdin) {
                self.reads(unit, Reads::Shell);
                continue;
            }
            self.runs_written(unit, &entry.file, unit.dir.as_ref());
            // A name an expansion made (`$PWD/e.sh`) is the file where the
            // line assigned it, whatever folder the shell runs from.
            if entry.expanded && entry.assigned.as_ref() != unit.dir.as_ref() {
                self.runs_written(unit, &entry.file, entry.assigned.as_ref());
            }
        }
    }

    /// `unit` runs `script`, from `dir`: say so when the line writes it, or
    /// may. From where `unit` runs, it is also judged from every other folder
    /// the line may be in then (see [`Unit::elsewhere`] and
    /// [`Unit::stayed`]): a `cd` that may not have run, or failed, after the
    /// line wrote the file, may have left it where the file is.
    fn runs_written(&mut self, unit: &Unit, script: &Arg, dir: Option<&Arg>) {
        let (others, stayed): (&[Option<Arg>], &[Option<Arg>]) = if dir == unit.dir.as_ref() {
            (&unit.elsewhere, &unit.stayed)
        } else {
            (&[], &[])
        };
        for from in
            std::iter::once(dir).chain(others.iter().chain(stayed.iter()).map(Option::as_ref))
        {
            let before = self.found.len();
            self.runs_written_from(unit, script, from);
            if self.found.len() != before {
                return;
            }
        }
    }

    /// `unit` runs `script`, with the line in `dir`: say so when the line
    /// writes it, or may.
    fn runs_written_from(&mut self, unit: &Unit, script: &Arg, dir: Option<&Arg>) {
        // A script path the guard cannot place (after a `cd` to somewhere
        // unknown, or on a drive whose directory is) may be the one the line
        // writes; a line that writes nothing has no script to be.
        if (!self.written.is_empty() || self.unplaced_write)
            && path::within(dir, script, unit.shell).is_unknown()
        {
            self.add(
                Rule::Unknown,
                "runs a script only known when it runs",
                Some(script),
            );
            return;
        }
        if script
            .known()
            .is_some_and(|text| self.pattern_written(dir, text, unit.shell))
        {
            self.add_run_written(script);
            return;
        }
        let Some(wanted) = self.resolver.file_key(dir, script, unit.shell) else {
            return;
        };
        if self.written.contains(&wanted) {
            self.add_run_written(script);
        }
    }
}

/// The word `arg` with each folder only known when it runs taken off the
/// front of a name the line wrote out (`"$PWD/.env"` after a `cd` to a name
/// that may hold code, `"$x/.env"`): the name, as the rules that follow a
/// secret read it, since a secret is named by its file name wherever the
/// folder is. `None` when no name is left to read or the word holds another
/// expansion past the last folder.
fn named_in_unknown_folder(arg: &Arg) -> Option<Arg> {
    let Arg::Template { text, .. } = arg else {
        return None;
    };
    let folder = format!("{}/", crate::posix::OPAQUE);
    if !text.contains(&folder) {
        return None;
    }
    let name = text.replace(&folder, "");
    (!name.contains(crate::posix::OPAQUE)).then_some(Arg::Known(name))
}

/// `unit` with its words read by the name they end in, for the rules that
/// follow a secret (`secret_read`, `send`, `secrets`): `curl -T "$PWD/.env"`
/// sends `.env` from wherever `$PWD` is. The words of any other rule stay as
/// the line wrote them, only known when it runs.
fn named(unit: &Unit) -> Cow<'_, Unit> {
    if unit.shell != Shell::Posix {
        return Cow::Borrowed(unit);
    }
    let names: Vec<Option<Arg>> = unit.args.iter().map(named_in_unknown_folder).collect();
    if names.iter().all(Option::is_none) {
        return Cow::Borrowed(unit);
    }
    let args = unit
        .args
        .iter()
        .zip(names)
        .map(|(arg, name)| name.unwrap_or_else(|| arg.clone()))
        .collect();
    Cow::Owned(Unit {
        args,
        ..Unit::clone(unit)
    })
}

/// The parameters of a listing stage: `Get-ChildItem` has switch aliases that
/// a prefix of a value parameter would take the folder for.
fn read_listing(unit: &Unit) -> Params<'_> {
    match unit.key().as_deref() {
        Some("get-childitem") => Params::read_listing(&unit.args),
        Some("get-item") => Params::read_item_listing(&unit.args),
        _ => Params::read(&unit.args),
    }
}

/// Whether a PowerShell listing is `-Force` or `-Hidden` (`-ah`), or has an
/// `-Attributes` value that may name hidden files (any it cannot read does),
/// which hands on the hidden files and folders (`.git`) as well.
fn lists_hidden(unit: &Unit) -> bool {
    if unit.shell != Shell::PowerShell
        || !matches!(unit.key().as_deref(), Some("get-childitem" | "get-item"))
    {
        return false;
    }
    let params = read_listing(unit);
    // The rest of a list (`-Attributes Directory,Hidden`) is a positional.
    let list_holds = |arg: &Arg| arg.known().is_none_or(holds_hidden);
    params.named.iter().any(|(name, value)| {
        (name.len() > 1 && "force".starts_with(name.as_str()))
            || "hidden".starts_with(name.as_str())
            || name == "ah"
            || ("attributes".starts_with(name.as_str())
                && (value.is_none_or(list_holds)
                    || params.positional.iter().any(|arg| list_holds(arg))))
    })
}

/// Whether an `-Attributes` value (`Hidden`, `h`, `!Directory+Hidden`,
/// `Directory,Hidden`) has a term that begins like `Hidden`, in any case.
fn holds_hidden(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|term| term.starts_with(['h', 'H']))
}

/// `name` inside the folder a listing of `text` hands on: the folder's last
/// part, a wildcard or not, is read as the folder itself.
fn inside(text: &str, name: &str) -> String {
    let last = text.rfind(['/', '\\']).map_or(0, |at| at + 1);
    let folder = if glob::has_wildcard(&text[last..]) {
        &text[..last]
    } else {
        text
    };
    let separator = if folder.is_empty() || folder.ends_with(['/', '\\']) {
        ""
    } else {
        "/"
    };
    format!("{folder}{separator}{name}")
}

/// The hidden files of a folder a listing hands on whole, read as `.*`.
fn hidden_files_of(arg: Arg) -> Arg {
    match &arg {
        Arg::Known(text) => Arg::Known(inside(text, ".*")),
        _ => arg,
    }
}

/// A pattern a hidden listing is filtered by, and whether it is a `-Filter`
/// value, which Windows PowerShell hands to the file system's own matching.
struct Pattern {
    arg: Arg,
    filter: bool,
}

/// The hidden files a `-Force` or `-Hidden` listing with a filter hands on:
/// each pattern as written, and `.git` itself when the pattern can match it
/// (`*`, `.g*`, `.git`). A `-Filter` is matched by the file system against
/// the 8.3 short name too, so one that can match `GIT~1` (`g*`, `*~1`,
/// `?????`) hands on `.git` as well; `-Include` is matched against the long
/// name only. When the listing recurses, the folders below are searched too,
/// so `.git` is handed on when a pattern can match one of the names it holds:
/// a top-level entry or a well-known file (`config` finds `.git\config`), a
/// well-known folder (`pack`, `heads`, `tags`, `remotes`, `origin`), or an
/// object by the shape of its name (`??` finds a loose object's folder, `1*` a
/// loose object or a pack). A pattern that is not known hands on every hidden
/// folder. What the pattern keeps that is not hidden is judged as
/// written, so `*.tmp` stays the files of the folder.
fn hidden_matches(places: &[Arg], patterns: &[Pattern], recurses: bool) -> Vec<Arg> {
    let mut found = Vec::new();
    if patterns.is_empty() {
        return found;
    }
    // Every place is matched with every pattern, and each path is resolved:
    // a long list of both is not read, and is handed on as unknown.
    if places.len().saturating_mul(patterns.len()) > MAX_HIDDEN_MATCHES {
        return vec![Arg::Unknown("<hidden listing>".to_string())];
    }
    for place in places {
        let Arg::Known(folder) = place else {
            continue;
        };
        for pattern in patterns {
            match &pattern.arg {
                Arg::Known(text) => {
                    // The resolver reads a wildcard with a `~` (`*~1`) as
                    // possibly a short name, which `-Include` never matches.
                    let written = if pattern.filter {
                        text.clone()
                    } else {
                        long_names_only(text)
                    };
                    found.push(Arg::Known(inside(folder, &written)));
                    // A `-Filter` is the file system's own matching: cmd's
                    // wildcards, the short name and all. `-Include` is
                    // PowerShell's, against the long name.
                    let names_git = if pattern.filter {
                        glob::can_match_git_folder(text)
                    } else {
                        glob::matches(text, ".git", Flavour::Windows, true)
                    };
                    let reaches_below = recurses
                        && if pattern.filter {
                            glob::can_match_git_entry(text, Flavour::Windows)
                        } else {
                            glob::can_match_git_entry_powershell(text)
                        };
                    if names_git || reaches_below {
                        found.push(Arg::Known(inside(folder, ".git")));
                    }
                }
                other => {
                    found.push(other.clone());
                    if recurses {
                        found.push(Arg::Known(inside(folder, ".*")));
                    }
                }
            }
        }
    }
    found
}

/// An `-Include` pattern written so the resolver reads it against long names
/// only: each `~` of a wildcard is put in a class (`*~1` is `*[~]1`), so it is
/// no longer a pattern for an 8.3 short name (`GIT~1`), which `-Include` is
/// never matched against. It picks the same long names. A text with no
/// wildcard, or with a class of its own (a `~` there is a member, and is not
/// to be put in another class), is as written.
fn long_names_only(text: &str) -> String {
    if glob::has_wildcard(text) && !text.contains('[') {
        text.replace('~', "[~]")
    } else {
        text.to_string()
    }
}

/// The most places times patterns a hidden listing is matched for; more is not
/// read, as every pair is a path to resolve.
const MAX_HIDDEN_MATCHES: usize = 256;

/// The paths a listing stage hands on.
fn listed(unit: &Unit) -> Option<Vec<Arg>> {
    if unit.key()?.as_str() == "find" && unit.shell == Shell::Posix {
        return Some(find_targets(&unit.args));
    }
    // What a hidden listing's filter may name, and whether it recurses.
    let mut patterns: Vec<Pattern> = Vec::new();
    let mut recurses = false;
    let (mut places, filtered): (Vec<Arg>, bool) = match unit.key()?.as_str() {
        "ls" if unit.shell != Shell::PowerShell => (
            operands(&unit.args, &[]).into_iter().cloned().collect(),
            false,
        ),
        "dir" if unit.shell == Shell::Cmd => {
            (plain(&unit.args).into_iter().cloned().collect(), false)
        }
        "get-childitem" | "get-item" => {
            let params = read_listing(unit);
            let mut places: Vec<Arg> = params
                .values(&["path", "literalpath"])
                .into_iter()
                .cloned()
                .collect();
            let has_path = !places.is_empty();
            places.extend(params.positional.iter().map(|arg| (*arg).clone()));
            let include = params.values(&["include"]);
            let pattern = |filter: bool| {
                move |arg: &Arg| Pattern {
                    arg: arg.clone(),
                    filter,
                }
            };
            patterns.extend(params.values(&["filter"]).into_iter().map(pattern(true)));
            patterns.extend(include.iter().copied().map(pattern(false)));
            let mut filtered = !patterns.is_empty();
            if lists_hidden(unit) {
                // `-Include a,b` and `-Attributes Directory,Hidden` leave
                // `b` among the positionals: it is not known to be a place,
                // so the folder listed is a place too, and what is left of
                // an `-Include` list is a pattern as well.
                let list = !include.is_empty()
                    || params
                        .named
                        .iter()
                        .any(|(name, _)| "attributes".starts_with(name.as_str()));
                if list && !has_path && !params.positional.is_empty() {
                    places.push(Arg::Known(".".to_string()));
                }
                if !include.is_empty() {
                    patterns.extend(params.positional.iter().copied().map(pattern(false)));
                }
            } else {
                // A listing that hands on no hidden file keeps its reading:
                // a filter or `-Exclude` narrows it to files inside the
                // folder, which `found_by` reads.
                patterns.clear();
                filtered |= !params.values(&["exclude"]).is_empty();
            }
            recurses = params.named.iter().any(|(name, _)| {
                "recurse".starts_with(name.as_str())
                    || "depth".starts_with(name.as_str())
                    || name == "s"
            });
            (places, filtered)
        }
        _ => return None,
    };
    if places.is_empty() {
        places.push(Arg::Known(".".to_string()));
    }
    let extra = hidden_matches(&places, &patterns, recurses);
    let mut found = found_by(places, filtered);
    found.extend(extra);
    Some(found)
}

/// What a listing of `places` finds, as paths the resolver reads.
fn found_by(places: Vec<Arg>, filtered: bool) -> Vec<Arg> {
    places
        .into_iter()
        .map(|place| match place {
            Arg::Known(text) => Arg::Known(path::listed(&text, filtered)),
            other => other,
        })
        .collect()
}

/// A destination given by `-t`, which is a folder: spelled with a trailing
/// separator, so that what lands in it is read as landing in a folder.
fn folder(arg: &Arg) -> Arg {
    match arg {
        Arg::Known(text) if !text.ends_with('/') => Arg::Known(format!("{text}/")),
        other => other.clone(),
    }
}

/// The options of `cp`, `install`, `mv` and `ln` that take a value, which is
/// not an operand.
const COPY_VALUED: [&str; 8] = [
    "-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group",
];

/// `mv`/`cp`-style operands: the sources and the destination, with `-t
/// DIR` (`-tDIR`, `--target-directory[=]DIR`) naming the destination when
/// given.
fn sources_and_destination<'a>(
    args: &'a [Arg],
    takes_value: &[&str],
) -> (Vec<&'a Arg>, Option<Arg>) {
    let mut operands = Vec::new();
    let mut target = None;
    let mut options = true;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known().filter(|_| options) else {
            operands.push(arg);
            continue;
        };
        if text == "--" {
            options = false;
        } else if text == "-t" || text == "--target-directory" {
            target = iter.next().map(folder);
        } else if let Some(dir) = text.strip_prefix("--target-directory=") {
            target = Some(folder(&Arg::Known(dir.to_string())));
        } else if takes_value.contains(&text) {
            iter.next();
        } else if text.starts_with("--") {
        } else if let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty()) {
            // `-t` in a bundle (`cp -rt DIR`) takes the rest of the bundle,
            // or the next argument when it ends the bundle.
            if let Some(at) = bundle.find('t') {
                let rest = &bundle[at + 1..];
                target = if rest.is_empty() {
                    iter.next().map(folder)
                } else {
                    Some(folder(&Arg::Known(rest.to_string())))
                };
            }
        } else {
            operands.push(arg);
        }
    }
    if target.is_some() {
        return (operands, target);
    }
    match operands.split_last() {
        Some((destination, sources)) if !sources.is_empty() => {
            (sources.to_vec(), Some((*destination).clone()))
        }
        _ => (Vec::new(), None),
    }
}

/// The files a unit writes, for matching a script the line then runs.
pub(crate) fn written_by(unit: &Unit) -> Vec<Arg> {
    let Some(key) = unit.key() else {
        return Vec::new();
    };
    let args = unit.args.as_slice();
    match key.as_str() {
        "curl" | "wget" if unit.shell != Shell::PowerShell => downloads_to(&key, args),
        "invoke-webrequest" | "invoke-restmethod" => Params::read(args)
            .values(&["outfile"])
            .into_iter()
            .cloned()
            .collect(),
        "cp" | "install" | "mv" | "ln" if unit.shell != Shell::PowerShell => {
            let (sources, destination) = sources_and_destination(args, &COPY_VALUED);
            destination.map_or_else(Vec::new, |destination| into_folder(&destination, &sources))
        }
        "copy-item" | "move-item" => {
            let params = Params::read(args);
            let mut sources = params.values(&["path", "literalpath"]);
            let mut positional = params.positional.iter().copied();
            // `Copy-Item a b` is `-Path a -Destination b`: a positional
            // is the source first, then the destination, each only where
            // no parameter names it.
            if sources.is_empty() {
                sources.extend(positional.next());
            }
            let destination = params
                .values(&["destination"])
                .first()
                .copied()
                .or_else(|| positional.next());
            destination.map_or_else(Vec::new, |destination| {
                into_folder(&or_here(destination), &sources)
            })
        }
        "tee" if unit.shell != Shell::PowerShell => {
            operands(args, &[]).into_iter().cloned().collect()
        }
        "set-content" | "add-content" | "out-file" | "tee-object" => content_files(args),
        "new-item" => new_item_files(args),
        "dd" => args
            .iter()
            .filter_map(|arg| arg.known()?.strip_prefix("of="))
            .map(|file| Arg::Known(file.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// The files `Set-Content`, `Add-Content`, `Out-File` and `Tee-Object`
/// write: the one `-Path`, `-LiteralPath` or `-FilePath` names, or, with none
/// given, the first operand (`Set-Content i.ps1 x`). The parser hands a list
/// of paths (`a.ps1,b.ps1`) over as separate words, which cannot be told from
/// a file and its value (`a.txt x.ps1`): so any other operand is a file too
/// (one only known when it runs as well: `Set-Content a.txt,$x y` names a
/// file that cannot be placed, see [`writes_by_cmdlet`]), and so is any
/// operand when a parameter the guard cannot tell takes a value or not may
/// have taken the first.
fn content_files(args: &[Arg]) -> Vec<Arg> {
    let params = Params::read(args);
    let mut files: Vec<Arg> = params
        .values(&["path", "literalpath", "filepath"])
        .into_iter()
        .cloned()
        .collect();
    let unclear = params.unclear();
    for (at, operand) in params.positional.iter().enumerate() {
        let first = at == 0 && files.is_empty();
        if first || unclear || is_name(operand) {
            files.push((*operand).clone());
        }
    }
    files
}

/// Whether `arg` is a word that can be a file's name: one the guard reads, or
/// one only known when it runs. Not the pipeline's input or `$null`.
fn is_name(arg: &Arg) -> bool {
    matches!(arg, Arg::Known(_) | Arg::Unknown(_) | Arg::Template { .. })
}

/// The cmdlets whose files [`written_by`] reads from their operands, where a
/// word in a list of paths is not told from a value: a file one of them names
/// only when it runs may be any file.
fn writes_by_cmdlet(unit: &Unit) -> bool {
    matches!(
        unit.key().as_deref(),
        Some("set-content" | "add-content" | "out-file" | "tee-object" | "new-item")
    )
}

/// The most files `New-Item` is read to create at once: each path is made with
/// each name, so a line of many of both is read as one file that is not
/// known.
const MAX_NEW_ITEMS: usize = 64;

/// The files `New-Item` creates: its path (named, or the first operand), or,
/// with `-Name`, each name inside that folder (the working folder when no
/// path is given). Any other operand is one more path, or one more name (a
/// list is handed over as separate words). A part only known when it runs is
/// kept as it is: the file cannot be placed, and any run of a script on the
/// line is judged for it (see [`writes_by_cmdlet`]).
fn new_item_files(args: &[Arg]) -> Vec<Arg> {
    let params = Params::read(args);
    let mut folders = params.values(&["path", "literalpath"]);
    let mut names = params.values(&["name"]);
    let mut operands = params.positional.iter().copied();
    if names.is_empty() {
        if folders.is_empty() {
            folders.extend(operands.next());
        }
        folders.extend(operands.filter(|operand| is_name(operand)));
        return folders.into_iter().cloned().collect();
    }
    // With `-Name` the first operand is the folder, or the first of a list
    // of names: it is read as both when no `-Path` says which.
    let here = Arg::Known(".".to_string());
    if folders.is_empty() {
        folders.push(&here);
        folders.extend(operands.clone().next());
    }
    names.extend(operands.filter(|operand| is_name(operand)));
    if folders.len().saturating_mul(names.len()) > MAX_NEW_ITEMS {
        return vec![Arg::Unknown("the files New-Item creates".to_string())];
    }
    let mut files = Vec::new();
    for folder in folders {
        for name in &names {
            match (folder, name) {
                (Arg::Known(folder), Arg::Known(name)) => {
                    let folder = folder.trim_end_matches(['/', '\\']);
                    files.push(Arg::Known(format!("{folder}/{name}")));
                }
                (Arg::Known(_), unknown) => files.push((*unknown).clone()),
                (unknown, _) => files.push(unknown.clone()),
            }
        }
    }
    files
}

/// A `$null` destination of `Copy-Item` or `Move-Item` is no destination, so
/// the item goes to the folder the line is in.
fn or_here(destination: &Arg) -> Arg {
    match destination {
        Arg::Null => Arg::Known(".".to_string()),
        other => other.clone(),
    }
}

/// What a copy to `destination` writes: the destination itself, or, as a
/// folder, each source's name inside it.
fn into_folder(destination: &Arg, sources: &[&Arg]) -> Vec<Arg> {
    let mut written = vec![destination.clone()];
    if let Arg::Known(folder) = destination {
        let folder = folder.trim_end_matches(['/', '\\']);
        for source in sources {
            if let Some(name) = source
                .known()
                .and_then(|path| path.rsplit(['/', '\\']).next())
                .filter(|name| !name.is_empty())
            {
                written.push(Arg::Known(format!("{folder}/{name}")));
            }
        }
    }
    written
}

/// The files `curl` or `wget` downloads into: `curl -o FILE` (also at the
/// end of a bundle, `-fsSLo FILE`), `curl -O` and plain `wget` (the URL's
/// last part), `wget -O FILE` (`-qO FILE`) and `-P DIR`.
fn downloads_to(key: &str, args: &[Arg]) -> Vec<Arg> {
    // curl's short options that take no value: only after these does an
    // `o` or `O` in a bundle start an option, not a value's letters.
    const CURL_FLAGS: &str = "sSLfkviI#N46ORZjlnqgGaBp";
    let (output, remote_flag, flags) = if key == "curl" {
        ('o', 'O', CURL_FLAGS)
    } else {
        ('O', '\0', "qvnNcrkpSxdFmb4")
    };
    let mut files = Vec::new();
    let mut remote = key == "wget";
    let mut prefix: Option<String> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        match text {
            "--output" | "--output-document" => {
                files.extend(iter.next().cloned());
                remote = false;
            }
            "--remote-name" | "--remote-name-all" => remote = true,
            "-P" | "--directory-prefix" => {
                prefix = iter.next().and_then(Arg::known).map(str::to_string);
            }
            _ => {
                if let Some(file) = text
                    .strip_prefix("--output=")
                    .or_else(|| text.strip_prefix("--output-document="))
                {
                    files.push(Arg::Known(file.to_string()));
                    remote = false;
                } else if let Some(dir) = text.strip_prefix("--directory-prefix=") {
                    prefix = Some(dir.to_string());
                } else if let Some(bundle) = text
                    .strip_prefix('-')
                    .filter(|bundle| !bundle.starts_with('-'))
                {
                    for (at, letter) in bundle.char_indices() {
                        if letter == remote_flag {
                            remote = true;
                        } else if letter == output {
                            let rest = &bundle[at + 1..];
                            if rest.is_empty() {
                                files.extend(iter.next().cloned());
                            } else {
                                files.push(Arg::Known(rest.to_string()));
                            }
                            remote = false;
                            break;
                        } else if !flags.contains(letter) {
                            break;
                        }
                    }
                }
            }
        }
    }
    if remote {
        for url in args
            .iter()
            .filter_map(Arg::known)
            .filter(|text| text.contains("://"))
        {
            let path = url.split(['?', '#']).next().unwrap_or(url);
            let name = path
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty() && !name.contains(':'))
                .unwrap_or("index.html");
            let file = prefix
                .as_deref()
                .map_or_else(|| name.to_string(), |dir| format!("{dir}/{name}"));
            files.push(Arg::Known(file));
        }
    }
    files.retain(|file| file.known() != Some("-"));
    files
}

/// The characters that separate the parts of a path in `shell`.
fn separators(shell: Shell) -> &'static [char] {
    if shell == Shell::Posix {
        &['/']
    } else {
        &['/', '\\']
    }
}

/// The script a shell or interpreter runs from a file: its first operand
/// after its options and their values; `None` for a module (`python -m`).
/// The modules the interpreter `key` loads before its script: node's (and
/// `tsx`'s and `ts-node`'s) `-r`, `--require`, `--import`, `--loader` and
/// `--experimental-loader` before the script, and bun's and deno's
/// `--preload`, `-r`, `--require` and `--import` anywhere before a `--`.
fn preloaded(key: &str, args: &[Arg]) -> Vec<Arg> {
    if is_node(key) {
        return options(key, args).preloads;
    }
    if key != "bun" && key != "deno" {
        return Vec::new();
    }
    const LOADS: [&str; 4] = ["--preload", "-r", "--require", "--import"];
    let mut found = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        if LOADS.contains(&text) {
            found.extend(iter.next().cloned());
        } else if let Some((option, value)) = text.split_once('=') {
            if LOADS.contains(&option) {
                found.push(Arg::Known(value.to_string()));
            }
        }
    }
    found
}

fn script_operand<'a>(key: &str, args: &'a [Arg]) -> Option<&'a Arg> {
    if matches!(key, "source" | ".") {
        return args.first();
    }
    // `uv run file.py` runs Python on the file.
    if key == "uv" {
        return uv_script(args);
    }
    // `bun run file` and `deno run file` run the file after the subcommand,
    // which may stand after options (`bun --hot run file`).
    let values: &[&str] = match key {
        "bun" => &BUN_VALUES,
        "deno" => &DENO_VALUES,
        _ if SHELLS.contains(&key) => &["-o", "+o", "-O", "+O", "--rcfile", "--init-file"],
        // An interpreter's script is read with its own table of options.
        _ => {
            let args = own_args(key, args);
            return options(key, args).script.map(|at| &args[at]);
        }
    };
    let args = match key {
        "bun" | "deno" => after_run(key, args),
        _ => args,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("-m") if !SHELLS.contains(&key) => return None,
            Some("--") => return iter.next(),
            Some(text) if values.contains(&text) => {
                iter.next();
            }
            Some(text) if text.len() > 1 && (text.starts_with('-') || text.starts_with('+')) => {}
            _ => return Some(arg),
        }
    }
    None
}
