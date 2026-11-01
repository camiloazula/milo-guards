//! The rules about files: what a line deletes, moves, copies and writes.

use super::{downloads_to, or_here, sources_and_destination, Checker, COPY_VALUED};
use crate::launch::{find_targets, perl_edits};
use crate::path::{Access, Place};
use crate::powershell::Params;
use crate::unit::{has_flag, has_switch, operands, plain, Arg, Scope, Unit};
use crate::{Rule, Shell};

impl Checker<'_> {
    /// Deleting, moving, copying and writing files.
    pub(super) fn files(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let shell = unit.shell;
        match key {
            // Deleting.
            "rm" | "unlink" | "srm" => self.delete(unit, &operands(args, &[]), "deletes"),
            "shred" => self.delete(
                unit,
                &operands(args, &["-n", "-s", "--iterations", "--size"]),
                "shreds",
            ),
            // Delete tools that come as packages (`npx rimraf dist`): the
            // paths are the operands, as for `rm`. `del --dry-run` only lists.
            "rimraf" | "del-cli" | "premove" | "rmrf" | "del"
                if key != "del" || shell == Shell::Posix =>
            {
                let dry = matches!(key, "del" | "del-cli") && has_flag(args, None, Some("dry-run"));
                if !dry {
                    self.delete(unit, &operands(args, &[]), "deletes");
                }
            }
            "find" if shell == Shell::Posix => {
                if args.iter().any(|arg| arg.known() == Some("-delete")) {
                    let found = find_targets(args);
                    self.delete(unit, &found.iter().collect::<Vec<_>>(), "deletes");
                }
            }
            "del" | "erase" if shell == Shell::Cmd => {
                let targets = builtin(&plain(args));
                self.delete(unit, &targets.iter().collect::<Vec<_>>(), "deletes");
            }
            "rd" | "rmdir" if shell == Shell::Cmd && has_switch(args, "s") => {
                let targets = builtin(&plain(args));
                self.delete(unit, &targets.iter().collect::<Vec<_>>(), "deletes");
            }
            "remove-item" => {
                let params = Params::read(args);
                let mut targets = params.values(&["path", "literalpath"]);
                targets.extend(params.positional.iter().copied());
                if targets.is_empty() && from_pipe(unit) {
                    self.delete(unit, &[&Arg::Input], "deletes");
                } else {
                    self.delete(unit, &targets, "deletes");
                }
            }
            "clear-recyclebin" => self.add(Rule::Delete, "empties the recycle bin", None),

            // Moving and copying: what is moved away, and where it lands.
            "mv" if shell != Shell::PowerShell => {
                let (sources, destination) = sources_and_destination(args, &["-S", "--suffix"]);
                self.move_away(unit, &sources, "moves");
                if let Some(destination) = destination {
                    self.copy_to(
                        shell,
                        unit.scope(),
                        &leaves(unit, &sources),
                        &destination,
                        false,
                    );
                }
            }
            "cp" | "install" if shell != Shell::PowerShell => {
                let recursive = key == "cp"
                    && (has_flag(args, Some('r'), Some("recursive"))
                        || has_flag(args, Some('R'), None)
                        || has_flag(args, Some('a'), Some("archive")));
                if let (sources, Some(destination)) = sources_and_destination(args, &COPY_VALUED) {
                    let leaves = leaves(unit, &sources);
                    self.copy_to(shell, unit.scope(), &leaves, &destination, recursive);
                }
            }
            "ln" if shell != Shell::PowerShell => {
                // A link reaches its target through a name inside the
                // workspace, so a later write or delete of the link lands on
                // whatever it points at.
                let (sources, destination) = sources_and_destination(args, &["-S", "--suffix"]);
                for source in &sources {
                    self.links_to(shell, unit.scope(), source);
                }
                if let Some(destination) = destination {
                    self.copy_to(
                        shell,
                        unit.scope(),
                        &leaves(unit, &sources),
                        &destination,
                        false,
                    );
                }
            }
            "copy" | "xcopy" | "move" if shell == Shell::Cmd => {
                let operands = builtin(&plain(args));
                let operands: Vec<&Arg> = operands.iter().collect();
                if key == "move" && operands.len() >= 2 {
                    self.move_away(unit, &operands[..operands.len() - 1], "moves");
                }
                if operands.len() >= 2 {
                    if let Some(destination) = operands.last() {
                        let recursive =
                            key == "xcopy" && (has_switch(args, "s") || has_switch(args, "e"));
                        let sources = &operands[..operands.len() - 1];
                        let leaves = leaves(unit, sources);
                        self.copy_to(shell, unit.scope(), &leaves, destination, recursive);
                    }
                }
            }
            "robocopy" => {
                let operands = plain(args);
                if let Some(destination) = operands.get(1) {
                    if has_switch(args, "mir") || has_switch(args, "purge") {
                        self.delete(unit, &[destination], "deletes files in");
                    }
                    // What it names after the two folders is what it copies;
                    // with none, every file of the first.
                    let named = leaves(unit, &operands[2..]);
                    let leaves = if named.is_empty() {
                        vec!["*".to_string()]
                    } else {
                        named
                    };
                    let recursive =
                        has_switch(args, "e") || has_switch(args, "s") || has_switch(args, "mir");
                    self.copy_to(shell, unit.scope(), &leaves, destination, recursive);
                }
            }
            "rsync" => {
                let operands = rsync_operands(args);
                if operands.len() >= 2 {
                    if let Some(destination) =
                        operands.last().filter(|destination| !remote(destination))
                    {
                        if args
                            .iter()
                            .any(|arg| arg.known().is_some_and(|text| text.starts_with("--delete")))
                        {
                            self.delete(unit, &[destination], "deletes files in");
                        }
                        let recursive = has_flag(args, Some('r'), Some("recursive"))
                            || has_flag(args, Some('a'), Some("archive"));
                        let sources = &operands[..operands.len() - 1];
                        let leaves = leaves(unit, sources);
                        self.copy_to(shell, unit.scope(), &leaves, destination, recursive);
                    }
                }
            }
            "copy-item" | "move-item" => {
                let params = Params::read(args);
                let paths = params.values(&["path", "literalpath"]);
                let recursive = key == "copy-item"
                    && params
                        .named
                        .iter()
                        .any(|(name, _)| "recurse".starts_with(name.as_str()));
                // `-Path` is position 0 and `-Destination` position 1. A
                // comma list of sources is flattened into the arguments, so
                // an operand after the first destination may be one more
                // source: each is read as the destination in turn, with the
                // rest as sources, and a risky reading wins.
                let mut readings: Vec<(Vec<&Arg>, &Arg)> = Vec::new();
                let mut operands = paths.clone();
                operands.extend(params.positional.iter().copied());
                if let Some(destination) = params.values(&["destination"]).first().copied() {
                    // What the pipeline hands it is a source too.
                    if operands.is_empty() && from_pipe(unit) {
                        operands.push(&Arg::Input);
                    }
                    readings.push((operands.clone(), destination));
                } else {
                    let first = paths.len().max(1);
                    for at in first..operands.len() {
                        let sources = (0..operands.len())
                            .filter(|other| *other != at)
                            .map(|other| operands[other])
                            .collect();
                        readings.push((sources, operands[at]));
                    }
                }
                if key == "move-item" {
                    let mut moved: Vec<&Arg> = Vec::new();
                    for source in readings.iter().flat_map(|(sources, _)| sources) {
                        if !moved.iter().any(|seen| std::ptr::eq(*seen, *source)) {
                            moved.push(source);
                        }
                    }
                    moved.retain(|source| **source != Arg::Input);
                    // With no path, what the stage before lists is moved.
                    let piped = if moved.is_empty() {
                        self.items(unit, &params)
                    } else {
                        Vec::new()
                    };
                    moved.extend(piped.iter());
                    self.move_away(unit, &moved, "moves");
                }
                for (sources, destination) in readings {
                    let leaves = leaves(unit, &sources);
                    // A `$null` destination is no destination: the item goes
                    // to the folder the line is in.
                    let destination = or_here(destination);
                    self.copy_to(shell, unit.scope(), &leaves, &destination, recursive);
                }
            }

            // Renaming: the new name is a name in the source's folder, and
            // that is where the file lands.
            "rename-item" if shell == Shell::PowerShell => {
                // `-NewName` (and what abbreviates it) is read as `-Name`,
                // which takes a value: the shared list of value parameters
                // is not changed for one cmdlet's own.
                let renamed_args: Vec<Arg> = args
                    .iter()
                    .map(|arg| {
                        let named = arg.known().and_then(|text| text.strip_prefix('-'));
                        let (name, colon) = match named {
                            Some(name) => match name.strip_suffix(':') {
                                Some(name) => (name, ":"),
                                None => (name, ""),
                            },
                            None => return arg.clone(),
                        };
                        if name.len() >= 2 && "newname".starts_with(&name.to_ascii_lowercase()) {
                            Arg::Known(format!("-Name{colon}"))
                        } else {
                            arg.clone()
                        }
                    })
                    .collect();
                let params = Params::read(&renamed_args);
                // What is renamed away is judged as the items the cmdlet
                // works on: a path, else what the stage before lists.
                let items = self.items(unit, &params);
                self.move_away(unit, &items.iter().collect::<Vec<_>>(), "renames");
                let mut sources = params.values(&["path", "literalpath"]);
                let mut positional = params.positional.iter().copied();
                if sources.is_empty() {
                    sources.extend(positional.next());
                }
                if sources.is_empty() && from_pipe(unit) {
                    sources.push(&Arg::Input);
                }
                let name = params
                    .values(&["name"])
                    .first()
                    .copied()
                    .or_else(|| positional.next());
                self.renamed_to(unit, &sources, name);
                // The new name is a name, not a path; one that holds a
                // separator is also a place the item is moved to.
                if let Some(name) = name.filter(|name| {
                    name.known()
                        .is_some_and(|name| name.contains(['\\', '/', ':']))
                }) {
                    self.write(shell, unit.scope(), name, "renames to");
                }
            }
            "ren" | "rename" if shell == Shell::Cmd => {
                let operands = builtin(&plain(args));
                if let [source, name, ..] = operands.as_slice() {
                    self.rename(unit, &[source], Some(name));
                }
            }
            // `rename` is util-linux's or perl's; the others are only perl's.
            "rename" | "rename.ul" if shell == Shell::Posix => self.rename_files(unit, false),
            "perl-rename" | "prename" | "file-rename" if shell == Shell::Posix => {
                self.rename_files(unit, true);
            }
            // `mklink [/d|/h|/j] link target` makes `link`.
            "mklink" if shell == Shell::Cmd => {
                if let [link, target, ..] = plain(args).as_slice() {
                    self.write(shell, unit.scope(), link, "writes to");
                    self.links_to(shell, unit.scope(), target);
                }
            }
            // A registry key or an item of another provider: judged by where
            // its path lands, as `Remove-Item` is.
            "clear-item" | "set-item" => {
                let verb = if key == "clear-item" {
                    "clears"
                } else {
                    "changes"
                };
                for target in self.list_items(unit, &Params::read(args), key == "set-item") {
                    self.write_as(shell, unit.scope(), &target, verb, Access::Item);
                }
            }

            // Writing into files.
            "truncate" => {
                for target in operands(args, &["-s", "--size", "-r", "--reference"]) {
                    self.write(shell, unit.scope(), target, "truncates");
                }
            }
            // Creating a file or folder beyond the workspace: `touch
            // ~/.hushlogin` changes what login does.
            "mkdir" | "touch" | "mkfifo" if shell != Shell::PowerShell => {
                for target in operands(
                    args,
                    &["-m", "--mode", "-r", "--reference", "-d", "--date", "-t"],
                ) {
                    if key == "mkdir" {
                        self.make_folder(shell, unit.scope(), target, Access::Content);
                    } else {
                        self.write(shell, unit.scope(), target, "creates");
                    }
                }
            }
            "md" if shell == Shell::Cmd => {
                for target in plain(args) {
                    self.make_folder(shell, unit.scope(), target, Access::Content);
                }
            }
            "sed" if has_flag(args, Some('i'), Some("in-place")) => {
                for file in sed_files(args) {
                    self.write(shell, unit.scope(), file, "edits");
                }
            }
            "perl" if shell == Shell::Posix => {
                for file in perl_edits(args).unwrap_or_default() {
                    self.write(shell, unit.scope(), file, "edits");
                }
            }
            "tee" if shell != Shell::PowerShell => {
                for target in operands(args, &[]) {
                    self.write(shell, unit.scope(), target, "writes to");
                }
            }
            "set-content" | "add-content" | "out-file" | "tee-object" | "new-item"
            | "clear-content" => {
                // `-Type` is `New-Item`'s other name for `-ItemType`.
                let owned: Vec<Arg>;
                let args = if key == "new-item" {
                    owned = args
                        .iter()
                        .map(|arg| match arg.known() {
                            Some(text) if text.eq_ignore_ascii_case("-type") => {
                                Arg::Known("-ItemType".to_string())
                            }
                            _ => arg.clone(),
                        })
                        .collect();
                    owned.as_slice()
                } else {
                    args
                };
                let params = Params::read(args);
                let mut targets: Vec<Arg> = params
                    .values(&["path", "literalpath", "filepath"])
                    .into_iter()
                    .cloned()
                    .collect();
                if targets.is_empty() {
                    targets.extend(params.positional.first().copied().cloned());
                }
                let verb = if key == "clear-content" {
                    "empties"
                } else {
                    "writes to"
                };
                // `Out-File` and `Tee-Object` need a file system path. `New-Item`
                // makes a key in the registry, and `Set-Content`, `Add-Content`
                // and `Clear-Content` take an item of the `Env:`, `Variable:`,
                // `Function:` and `Alias:` providers (`Set-Content NUL ...`
                // in `Function:` defines a function named NUL).
                let access = if matches!(key, "out-file" | "tee-object") {
                    Access::Content
                } else {
                    Access::Item
                };
                if key == "new-item" {
                    // With `-Name` the path is optional: no path, or a `$null`
                    // one, makes the item in the folder the line is in.
                    targets = targets.iter().map(or_here).collect();
                    if targets.is_empty() {
                        targets.push(Arg::Known(".".to_string()));
                    }
                    // The item is `Path\Name`, with any `..` in the name
                    // applied, so a device path is never the item itself.
                    let names = params.values(&["name"]);
                    if !names.is_empty() {
                        targets = targets
                            .iter()
                            .flat_map(|path| names.iter().map(|name| item_path(path, name)))
                            .collect();
                    }
                }
                let kind = params.values(&["itemtype"]);
                let kind = kind.first().and_then(|kind| kind.known());
                // `New-Item -ItemType Directory` makes a folder, not a file.
                let folder = key == "new-item"
                    && kind.is_some_and(|kind| kind.to_ascii_lowercase().starts_with('d'));
                for target in &targets {
                    if folder {
                        self.make_folder(shell, unit.scope(), target, access);
                    } else {
                        self.write_as(shell, unit.scope(), target, verb, access);
                    }
                }
                // A link reaches what it names, as `ln` does.
                let link = kind.is_some_and(|kind| {
                    let kind = kind.to_ascii_lowercase();
                    ["s", "h", "j"].iter().any(|first| kind.starts_with(first))
                });
                if key == "new-item" && link {
                    for value in params.values(&["value"]) {
                        self.links_to(shell, unit.scope(), value);
                    }
                }
            }
            "set-itemproperty"
            | "new-itemproperty"
            | "remove-itemproperty"
            | "clear-itemproperty"
            | "rename-itemproperty" => {
                let params = Params::read(args);
                let mut targets = params.values(&["path", "literalpath"]);
                if targets.is_empty() {
                    targets.extend(params.positional.first().copied());
                }
                for target in targets {
                    self.write_as(shell, unit.scope(), target, "changes", Access::Item);
                }
            }
            // A value moved or copied between keys: the path, the destination and
            // any argument that may stand for either are judged.
            "copy-itemproperty" | "move-itemproperty" => {
                let params = Params::read(args);
                let mut targets = params.values(&["path", "literalpath", "destination"]);
                targets.extend(params.positional.iter().copied());
                for target in targets {
                    self.write_as(shell, unit.scope(), target, "changes", Access::Item);
                }
            }
            "dd" => {
                for arg in args {
                    if let Some(file) = arg.known().and_then(|text| text.strip_prefix("of=")) {
                        self.write(
                            shell,
                            unit.scope(),
                            &Arg::Known(file.to_string()),
                            "writes to",
                        );
                    }
                }
            }
            "curl" | "wget" if shell != Shell::PowerShell => {
                for file in downloads_to(key, args) {
                    self.write(shell, unit.scope(), &file, "writes to");
                }
            }
            "invoke-webrequest" | "invoke-restmethod" => {
                if let Some(file) = Params::read(args).values(&["outfile"]).first() {
                    self.write(shell, unit.scope(), file, "writes to");
                }
            }

            _ => {}
        }
    }
}

/// The path of the item `New-Item -Path PATH -Name NAME` makes: `PATH\NAME`,
/// only known when either is.
fn item_path(path: &Arg, name: &Arg) -> Arg {
    match (path, name) {
        (Arg::Known(path), Arg::Known(name)) => {
            Arg::Known(format!("{}/{name}", path.trim_end_matches(['/', '\\'])))
        }
        (Arg::Known(path), Arg::Null) => Arg::Known(path.clone()),
        (path, name) => Arg::Unknown(format!("{}/{}", path.text(), name.text())),
    }
}

impl Checker<'_> {
    /// A link whose target is `source`: a later write through the link lands
    /// on whatever it points at, so a target beyond the workspace is a
    /// finding.
    fn links_to(&mut self, shell: Shell, scope: Scope<'_>, source: &Arg) {
        let place = self.place(shell, scope, source, Access::Item);
        if !place.harmless() && !matches!(place, Place::Workspace { exact: true }) {
            self.add(
                Rule::Overwrite,
                format!("links to {}", place.words()),
                Some(source),
            );
        }
    }

    /// A rename of `sources` to the name `name`: what is moved away is
    /// judged as `mv` judges it, and the new name, in each source's folder,
    /// is written. A name that is not known, or a source whose folder is
    /// not, is a file only known when it runs.
    fn rename(&mut self, unit: &Unit, sources: &[&Arg], name: Option<&Arg>) {
        let moved: Vec<&Arg> = sources
            .iter()
            .copied()
            .filter(|source| **source != Arg::Input)
            .collect();
        self.move_away(unit, &moved, "moves");
        self.renamed_to(unit, sources, name);
    }

    /// The new name of a rename, in each source's folder: written.
    fn renamed_to(&mut self, unit: &Unit, sources: &[&Arg], name: Option<&Arg>) {
        let Some(name) = name else { return };
        let none = Arg::Known(String::new());
        let sources = if sources.is_empty() {
            vec![&none]
        } else {
            sources.to_vec()
        };
        for source in sources {
            let (found, _) = self.expand(unit, source);
            for from in found {
                let to = renamed(&from, name);
                self.write_as(unit.shell, unit.scope(), &to, "writes to", Access::Item);
            }
        }
    }

    /// The `rename` of util-linux (`perl` says it is perl's), `rename FROM TO file...`, whose new names
    /// are plain text: the first `FROM` in each name (every one, with `-a`)
    /// becomes `TO`. Only these options are read: `-v`, `-n`, `-o`, `-s`,
    /// `-i`, `-a` and their long forms; any other changes what the new name
    /// is, and so does an expression, which is perl's `rename` and code the
    /// guard does not read. Both leave the new name of each file, in its own
    /// folder, unknown. What is renamed away is judged as `mv` judges it.
    fn rename_files(&mut self, unit: &Unit, perl: bool) {
        const KNOWN: [&str; 6] = [
            "--verbose",
            "--no-act",
            "--no-overwrite",
            "--symlink",
            "--interactive",
            "--all",
        ];
        let mut all = false;
        let mut unread = false;
        let mut operands: Vec<&Arg> = Vec::new();
        let mut options = true;
        for arg in &unit.args {
            let Some(text) = arg.known().filter(|_| options) else {
                operands.push(arg);
                continue;
            };
            if text == "--" {
                options = false;
            } else if let Some(long) = text.strip_prefix("--") {
                unread |= !KNOWN.contains(&text) || long.contains('=');
                all |= text == "--all";
            } else if let Some(bundle) = text.strip_prefix('-').filter(|b| !b.is_empty()) {
                unread |= !bundle.chars().all(|c| "vnosia".contains(c));
                all |= bundle.contains('a');
            } else {
                operands.push(arg);
            }
        }
        // An expression is perl's: it takes the place of `FROM TO`, so there
        // are fewer than three operands, or the first is not plain text.
        let code = perl
            || operands.len() < 3
            || operands[0].known().is_none_or(|first| {
                first.contains(|c: char| "$@;(){}=|\\[]*+?^'\"`".contains(c) || c.is_whitespace())
            });
        if code && !unread && !operands.is_empty() {
            self.add(
                Rule::Unknown,
                "runs code the guard does not read",
                operands.first().copied(),
            );
        } else if unread {
            self.add(
                Rule::Unknown,
                "renames with options the guard does not read",
                operands.first().copied(),
            );
        }
        let pair = match operands.as_slice() {
            [from, to, ..] if !code && !unread => from.known().zip(to.known()),
            _ => None,
        };
        let Some((from, to)) = pair else {
            // Every operand can be a file, and what it becomes is unknown: a
            // `TO` only known when it runs is no better.
            // The expression is the first operand, and no file.
            let named = if code && !unread && !operands.is_empty() {
                &operands[1..]
            } else {
                &operands[..]
            };
            self.move_away(unit, named, "moves");
            for operand in named {
                let to = Arg::Unknown(operand.text().to_string());
                self.write(unit.shell, unit.scope(), &to, "writes to");
            }
            return;
        };
        let files = &operands[2..];
        for file in files {
            let new = match file.known() {
                Some(text) if !from.is_empty() => Arg::Known(replace(text, from, to, all)),
                Some(text) => Arg::Known(text.to_string()),
                None => Arg::Unknown(file.text().to_string()),
            };
            if file.known() == new.known() && new.known().is_some() {
                continue;
            }
            self.move_away(unit, &[file], "moves");
            self.write(unit.shell, unit.scope(), &new, "writes to");
        }
    }
}

/// `text` with the first `from` in it (every one, with `all`) replaced.
fn replace(text: &str, from: &str, to: &str, all: bool) -> String {
    if all {
        text.replace(from, to)
    } else {
        text.replacen(from, to, 1)
    }
}

/// The path of the name `name` in the folder `from` is in (`from` itself
/// ends in a separator when it is the folder); unknown when either is.
fn renamed(from: &Arg, name: &Arg) -> Arg {
    let (Some(from), Some(name)) = (from.known(), name.known()) else {
        return Arg::Unknown(name.text().to_string());
    };
    let folder = from.rfind(['/', '\\']).map_or("", |at| &from[..=at]);
    Arg::Known(format!("{folder}{name}"))
}

/// Whether a PowerShell cmdlet given no path works on its pipeline input.
fn from_pipe(unit: &Unit) -> bool {
    unit.stage.is_some_and(|stage| stage.index > 0)
}

/// cmd's built-in commands (`del`, `rd`, `copy`, `move`) also end an
/// argument at `,`, `;` and `=`: `rd /s /q x,C:\Users\me` is two folders.
fn builtin(args: &[&Arg]) -> Vec<Arg> {
    args.iter()
        .flat_map(|arg| match arg {
            Arg::Known(text) => text
                .split([',', ';', '='])
                .filter(|part| !part.is_empty())
                .map(|part| Arg::Known(part.to_string()))
                .collect::<Vec<_>>(),
            other => vec![(*other).clone()],
        })
        .collect()
}

/// The files `sed -i` edits: its operands after the script (the first
/// operand, unless `-e` or `-f` gives it). BSD's `-i ''` and `-i .bak` take
/// the suffix as the next argument.
fn sed_files(args: &[Arg]) -> Vec<&Arg> {
    let mut script_given = false;
    let mut operands = Vec::new();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("--") => {
                operands.extend(iter.by_ref());
                break;
            }
            Some("-e" | "-f" | "--expression" | "--file") => {
                script_given = true;
                iter.next();
            }
            Some("-i") => {
                if iter
                    .peek()
                    .and_then(|next| next.known())
                    .is_some_and(|next| next.is_empty() || next.starts_with('.'))
                {
                    iter.next();
                }
            }
            Some("-l" | "--line-length") => {
                iter.next();
            }
            Some(text) if text.starts_with("--expression=") || text.starts_with("--file=") => {
                script_given = true;
            }
            Some(text) if text.len() > 1 && text.starts_with('-') => {}
            _ => operands.push(arg),
        }
    }
    if !script_given && !operands.is_empty() {
        operands.remove(0);
    }
    operands
}

/// An rsync `host:path` operand, which is not on this machine.
pub(super) fn remote(arg: &Arg) -> bool {
    arg.known().is_some_and(|text| {
        text.find(':')
            .is_some_and(|colon| colon > 1 && !text[..colon].contains('/'))
    })
}

/// The name each source lands as inside a folder it is copied into: its last
/// part. A source that is not known, what a pipeline hands on, or what `find`
/// found (`-exec cp {} dest \;`) lands as a name that could be anything (`*`),
/// and `.` or `..` (the contents of a folder) has no name of its own.
fn leaves(unit: &Unit, sources: &[&Arg]) -> Vec<String> {
    let shell = unit.shell;
    let found = unit.wrappers.iter().any(|wrapper| wrapper == "find");
    let separators: &[char] = if shell == Shell::Posix {
        &['/']
    } else {
        &['/', '\\']
    };
    sources
        .iter()
        .flat_map(|source| {
            let text = match source.known() {
                Some(text) if !found => text,
                _ => return vec![Some("*".to_string())],
            };
            // cmd's `copy a+b dest` joins files into one named like the first.
            let texts: Vec<&str> = if shell == Shell::Cmd {
                text.split('+').collect()
            } else {
                vec![text]
            };
            texts
                .into_iter()
                .map(
                    |text| match text.trim_end_matches(separators).rsplit(separators).next() {
                        None | Some("" | "." | ".." | "~") => None,
                        Some(name) => Some(name.to_string()),
                    },
                )
                .collect()
        })
        .flatten()
        .collect()
}

/// What rsync is given to copy and where: the operands, not the values of
/// its options that take one.
pub(super) fn rsync_operands(args: &[Arg]) -> Vec<&Arg> {
    operands(
        args,
        &[
            "-e",
            "--rsh",
            "--exclude",
            "--include",
            "--filter",
            "-f",
            "--files-from",
            "--exclude-from",
            "--include-from",
            "--log-file",
            "--password-file",
            "--port",
            "--backup-dir",
            "--suffix",
            "-T",
            "--temp-dir",
            "--chmod",
            "--chown",
            "--compare-dest",
            "--copy-dest",
            "--link-dest",
            "--partial-dir",
            "--timeout",
            "--bwlimit",
        ],
    )
}
