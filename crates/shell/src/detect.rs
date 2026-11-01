//! The rules: each reads a unit's program, flags, operands and redirects,
//! and judges every path by where it resolves.

use crate::launch::{
    after_run, find_targets, uv_script, BUN_VALUES, DENO_VALUES, INTERPRETERS, SHELLS,
};
use crate::path::{self, Access, Place, Resolver};
use crate::powershell::Params;
use milo_guards_core::spelling::glob;

use std::collections::HashMap;

use crate::unit::{operands, plain, Arg, Reads, Scope, Split, Unit};
use crate::{Finding, Rule, Shell};
use milo_guards_core::Flavour;

mod code;
mod files;
mod secrets;
mod send;
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

/// Programs that download, whose output piped into a shell is a downloaded
/// script.
const DOWNLOADERS: [&str; 10] = [
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
    let mut checker = Checker {
        split,
        resolver,
        found: split.findings.clone(),
        written: Vec::new(),
        unplaced_write: false,
        downloaders: HashMap::new(),
        producers: HashMap::new(),
        flow: send::Flow::default(),
    };
    // Indexed once, so each unit's pipeline questions are lookups, not
    // scans of every unit.
    for (at, unit) in split.units.iter().enumerate() {
        if let Some(stage) = unit.stage {
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
        }
        for target in written_by(unit) {
            checker.written(unit.dir.as_ref(), &target, unit.shell);
        }
    }
    for write in &split.writes {
        checker.written(write.dir.as_ref(), &write.target, write.shell);
    }
    checker.flow = checker.trace();
    // What each step adds to `found` is what that step found: the findings
    // from `split.findings` come first, and are the line's own.
    let mut line = checker.found.clone();
    let mut units = Vec::with_capacity(split.units.len());
    for (at, unit) in split.units.iter().enumerate() {
        let before = checker.found.len();
        checker.unit(at, unit);
        units.push(checker.found[before..].to_vec());
    }
    // A read through `<` is not a unit's: it belongs to the line.
    let before = checker.found.len();
    checker.redirected_reads();
    line.extend_from_slice(&checker.found[before..]);
    let mut writes = Vec::with_capacity(split.writes.len());
    for write in &split.writes {
        let before = checker.found.len();
        checker.write(write.shell, write.scope(), &write.target, "writes to");
        writes.push(checker.found[before..].to_vec());
    }
    let mut seen = std::collections::HashSet::new();
    checker.found.retain(|finding| seen.insert(finding.clone()));
    Judged {
        found: checker.found,
        line,
        units,
        writes,
    }
}

struct Checker<'a> {
    split: &'a Split,
    resolver: &'a Resolver,
    found: Vec<Finding>,
    /// Every file the line writes, by [`Resolver::file_key`]: redirects,
    /// downloads, copies, `tee`, `dd`.
    written: Vec<String>,
    /// Whether the line writes a file it cannot place (a target known only
    /// when it runs, or after a `cd` to such a place): it has no key, but
    /// may be a script the line runs.
    unplaced_write: bool,
    /// For each pipeline, the first stage that downloads.
    downloaders: HashMap<usize, usize>,
    /// The first unit at each pipeline stage, by its index in the split.
    producers: HashMap<(usize, usize), usize>,
    /// Where secrets are read and where they go, for the rule that finds
    /// them sent away.
    flow: send::Flow,
}

impl Checker<'_> {
    /// Note a file the line writes, from `dir`.
    fn written(&mut self, dir: Option<&Arg>, target: &Arg, shell: Shell) {
        if let Some(key) = self.resolver.file_key(dir, target, shell) {
            self.written.push(key);
        } else if self.resolver.unplaced(dir, target, shell) {
            self.unplaced_write = true;
        }
    }

    fn add(&mut self, rule: Rule, reason: impl Into<String>, target: Option<&Arg>) {
        self.found.push(Finding {
            rule,
            reason: reason.into(),
            target: target.map(|arg| arg.text().to_string()),
        });
    }

    fn unit(&mut self, at: usize, unit: &Unit) {
        self.called(unit);
        let Some(key) = unit.key() else {
            return;
        };
        self.elevated(unit, &key);
        self.reads(unit);
        self.secrets(at, unit, &key);
        self.write_then_run(unit, &key);
        self.files(unit, &key);
        self.send(at, unit, &key);
        self.system(unit, &key);
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
    fn reads(&mut self, unit: &Unit) {
        let downloaded = unit.stage.is_some_and(|stage| {
            self.downloaders
                .get(&stage.pipeline)
                .is_some_and(|&first| first < stage.index)
        });
        match (unit.reads, downloaded) {
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
    /// names.
    fn expand(&self, unit: &Unit, arg: &Arg) -> (Vec<Arg>, bool) {
        if *arg != Arg::Input {
            return (vec![arg.clone()], false);
        }
        let producer = unit
            .stage
            .filter(|stage| stage.index > 0)
            .and_then(|stage| self.producers.get(&(stage.pipeline, stage.index - 1)))
            .and_then(|&at| self.split.units.get(at));
        let found = producer
            .and_then(listed)
            .unwrap_or_else(|| vec![Arg::Unknown("<input>".to_string())]);
        (
            found,
            producer.is_some_and(|producer| producer.hidden || lists_hidden(producer)),
        )
    }

    fn delete(&mut self, unit: &Unit, targets: &[&Arg], verb: &str) {
        for target in targets {
            let (found, listed_hidden) = self.expand(unit, target);
            let scope = Scope {
                hidden: unit.hidden || listed_hidden,
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

    /// A write of `target`, by how it reaches it (see [`Access`]).
    fn write_as(
        &mut self,
        shell: Shell,
        scope: Scope<'_>,
        target: &Arg,
        verb: &str,
        access: Access,
    ) {
        match self.place_into(shell, scope, target, access) {
            place if place.harmless() => {}
            Place::Workspace { exact: true } | Place::Temp { exact: true } => {}
            Place::Disk => self.add(Rule::WipeDisk, "writes over a disk", Some(target)),
            Place::Registry => self.add(Rule::SystemSettings, "changes the registry", Some(target)),
            Place::Outside => self.add(
                Rule::Overwrite,
                format!("{verb} a file outside the workspace"),
                Some(target),
            ),
            Place::Unknown => self.add(
                Rule::Overwrite,
                format!("{verb} a file only known when it runs"),
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
        let folder_for_sure = leaves.len() > 1
            || text.ends_with(separators)
            || matches!(text.rsplit(separators).next(), Some("." | ".."));
        for leaf in leaves {
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
    /// what it does is not in the line.
    fn write_then_run(&mut self, unit: &Unit, key: &str) {
        let runner = SHELLS.contains(&key)
            || INTERPRETERS.contains(&key)
            || key == "uv"
            || key.starts_with("python3.")
            || (unit.shell == Shell::Posix && matches!(key, "source" | "."));
        if !runner {
            return;
        }
        let Some(script) = script_operand(key, &unit.args) else {
            return;
        };
        // A script path the guard cannot place (after a `cd` to somewhere
        // unknown, or on a drive whose directory is) may be the one the line
        // writes; a line that writes nothing has no script to be.
        if (!self.written.is_empty() || self.unplaced_write)
            && path::within(unit.dir.as_ref(), script, unit.shell).is_unknown()
        {
            self.add(
                Rule::Unknown,
                "runs a script only known when it runs",
                Some(script),
            );
            return;
        }
        let Some(wanted) = self
            .resolver
            .file_key(unit.dir.as_ref(), script, unit.shell)
        else {
            return;
        };
        if self.written.contains(&wanted) {
            self.add(
                Rule::Unknown,
                "runs a script the same line writes",
                Some(script),
            );
        }
    }
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
                    found.push(Arg::Known(inside(folder, text)));
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
fn written_by(unit: &Unit) -> Vec<Arg> {
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
            let sources = params.values(&["path", "literalpath"]);
            params
                .values(&["destination"])
                .first()
                .map_or_else(Vec::new, |destination| {
                    into_folder(&or_here(destination), &sources)
                })
        }
        "tee" if unit.shell != Shell::PowerShell => {
            operands(args, &[]).into_iter().cloned().collect()
        }
        "set-content" | "add-content" | "out-file" | "tee-object" => Params::read(args)
            .values(&["path", "literalpath", "filepath"])
            .into_iter()
            .cloned()
            .collect(),
        "dd" => args
            .iter()
            .filter_map(|arg| arg.known()?.strip_prefix("of="))
            .map(|file| Arg::Known(file.to_string()))
            .collect(),
        _ => Vec::new(),
    }
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

/// The script a shell or interpreter runs from a file: its first operand
/// after its options and their values; `None` for a module (`python -m`).
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
        _ => &["-W", "-X", "-r", "--require", "--import", "--loader"],
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
