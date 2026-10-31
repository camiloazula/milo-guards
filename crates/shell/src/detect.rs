//! The rules: each reads a unit's program, flags, operands and redirects,
//! and judges every path by where it resolves.

use crate::launch::{find_targets, INTERPRETERS, SHELLS};
use crate::path::{self, Place, Resolver};
use crate::powershell::Params;

use std::collections::HashMap;

use crate::unit::{operands, plain, Arg, Reads, Scope, Split, Unit};
use crate::{Finding, Rule, Shell};
use milo_guards_core::spelling::glob;

mod code;
mod files;
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

pub(crate) fn findings(split: &Split, resolver: &Resolver) -> Vec<Finding> {
    let mut checker = Checker {
        split,
        resolver,
        found: split.findings.clone(),
        written: Vec::new(),
        unplaced_write: false,
        downloaders: HashMap::new(),
        producers: HashMap::new(),
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
    for unit in &split.units {
        checker.unit(unit);
    }
    for write in &split.writes {
        checker.write(write.shell, write.scope(), &write.target, "writes to");
    }
    let mut seen = std::collections::HashSet::new();
    checker.found.retain(|finding| seen.insert(finding.clone()));
    checker.found
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

    fn unit(&mut self, unit: &Unit) {
        let Some(key) = unit.key() else {
            return;
        };
        self.elevated(unit, &key);
        self.reads(unit);
        self.write_then_run(unit, &key);
        self.files(unit, &key);
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
        (found, producer.is_some_and(|producer| producer.hidden))
    }

    fn delete(&mut self, unit: &Unit, targets: &[&Arg], verb: &str) {
        for target in targets {
            let (found, listed_hidden) = self.expand(unit, target);
            let scope = Scope {
                hidden: unit.hidden || listed_hidden,
                ..unit.scope()
            };
            for arg in found {
                match self.place(unit.shell, scope, &arg) {
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
            let place = self.place(unit.shell, unit.scope(), source);
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

    /// The items `Clear-Item` and `Set-Item` act on: every `-Path` and
    /// `-LiteralPath` value and every positional, as `Remove-Item` reads
    /// them, since both take a list of paths. With no path named and no
    /// `-Value`, `Set-Item` takes its value as the last positional, which is
    /// not a path (unless it is the only one). With a path named, a
    /// positional may be the rest of the list (`-Path a,b`), so each is
    /// judged.
    fn list_items(&self, unit: &Unit, params: &Params<'_>, value_last: bool) -> Vec<Arg> {
        let mut paths = params.values(&["path", "literalpath"]);
        let positional = &params.positional;
        let value_named = params
            .named
            .iter()
            .any(|(name, _)| "value".starts_with(name.as_str()));
        let count = if value_last && !value_named && paths.is_empty() && positional.len() > 1 {
            positional.len() - 1
        } else {
            positional.len()
        };
        paths.extend(positional.iter().take(count).copied());
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
    /// hands on what is inside it, so that place is dropped; `Get-Item` hands
    /// on the item itself, so only a pattern of its (`Get-Item *`) is dropped
    /// and a workspace root named as written is kept.
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
            .filter(|arg| {
                let named = item && !matches!(arg, Arg::Known(text) if glob::has_wildcard(text));
                named
                    || !matches!(
                        self.place(unit.shell, scope, arg),
                        Place::Workspace { exact: true }
                    )
            })
            .collect()
    }

    /// Where `arg` lands, run from `dir` where a `cd` moved.
    fn place(&self, shell: Shell, scope: Scope<'_>, arg: &Arg) -> Place {
        self.resolver
            .place(&path::within(scope.dir, arg, shell), shell, scope.hidden)
    }

    fn write(&mut self, shell: Shell, scope: Scope<'_>, target: &Arg, verb: &str) {
        match self.place(shell, scope, target) {
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

    fn permissions(&mut self, unit: &Unit, targets: &[&Arg], verb: &str) {
        for target in targets {
            match self.place(unit.shell, unit.scope(), target) {
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

/// The paths a listing stage hands on.
fn listed(unit: &Unit) -> Option<Vec<Arg>> {
    if unit.key()?.as_str() == "find" && unit.shell == Shell::Posix {
        return Some(find_targets(&unit.args));
    }
    let (places, filtered) = match unit.key()?.as_str() {
        "ls" if unit.shell != Shell::PowerShell => (
            operands(&unit.args, &[]).into_iter().cloned().collect(),
            false,
        ),
        "dir" if unit.shell == Shell::Cmd => {
            (plain(&unit.args).into_iter().cloned().collect(), false)
        }
        "get-childitem" | "get-item" => {
            let params = Params::read(&unit.args);
            let mut places: Vec<Arg> = params
                .values(&["path", "literalpath"])
                .into_iter()
                .cloned()
                .collect();
            places.extend(params.positional.iter().map(|arg| (*arg).clone()));
            let filtered = !params.values(&["filter", "include", "exclude"]).is_empty();
            (places, filtered)
        }
        _ => return None,
    };
    let places = if places.is_empty() {
        vec![Arg::Known(".".to_string())]
    } else {
        places
    };
    Some(found_by(places, filtered))
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
            target = iter.next().cloned();
        } else if let Some(dir) = text.strip_prefix("--target-directory=") {
            target = Some(Arg::Known(dir.to_string()));
        } else if takes_value.contains(&text) {
            iter.next();
        } else if text.starts_with("--") {
        } else if let Some(bundle) = text.strip_prefix('-').filter(|bundle| !bundle.is_empty()) {
            // `-t` in a bundle (`cp -rt DIR`) takes the rest of the bundle,
            // or the next argument when it ends the bundle.
            if let Some(at) = bundle.find('t') {
                let rest = &bundle[at + 1..];
                target = if rest.is_empty() {
                    iter.next().cloned()
                } else {
                    Some(Arg::Known(rest.to_string()))
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
            let (sources, destination) = sources_and_destination(
                args,
                &[
                    "-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group",
                ],
            );
            destination.map_or_else(Vec::new, |destination| into_folder(&destination, &sources))
        }
        "copy-item" | "move-item" => {
            let params = Params::read(args);
            let sources = params.values(&["path", "literalpath"]);
            params
                .values(&["destination"])
                .first()
                .map_or_else(Vec::new, |destination| into_folder(destination, &sources))
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
    let values: &[&str] = if SHELLS.contains(&key) {
        &["-o", "+o", "-O", "+O", "--rcfile", "--init-file"]
    } else {
        &["-W", "-X", "-r", "--require", "--import", "--loader"]
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
