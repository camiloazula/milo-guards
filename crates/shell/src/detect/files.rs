//! The rules about files: what a line deletes, moves, copies and writes.

use super::{dd_outputs, downloads_to, or_here, sources_and_destination, Checker, COPY_VALUED};
use crate::launch::{find_targets, find_unread_primary, perl_edits};
use crate::path::{Access, Place};
use crate::powershell::Params;
use crate::unit::{
    could_be, flagged, has_flag, has_switch, may_be_option, operands, operands_split, plain,
    switch_names, switch_value, unread_option, Arg, Flagged, Scope, Unit,
};
use crate::{Rule, Shell};
use milo_guards_core::spelling::{glob, verbatim};
use milo_guards_core::Flavour;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

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
                &operands_split(args, &["-n", "-s", "--iterations", "--size"], shell),
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
            // An argument only known when it runs that may be the option
            // that deletes (`-delete`, `--delete`, `/MIR`) or edits in place
            // (`-i`) is taken as given, and the finding says it may: one
            // that may split into words, one that starts with `-`, and in
            // find's expression any that is not a test's value.
            "find" if shell == Shell::Posix => {
                let flagged = Flagged::of(
                    args.iter().any(|arg| arg.known() == Some("-delete")),
                    unread_option(args, shell) || find_unread_primary(args),
                );
                self.flagged(flagged, |checker| {
                    let found = find_targets(args);
                    checker.delete(unit, &found.iter().collect::<Vec<_>>(), "deletes");
                });
            }
            "del" | "erase" if shell == Shell::Cmd => {
                let targets = builtin(key, args);
                self.delete(unit, &targets.iter().collect::<Vec<_>>(), "deletes");
                if has_switch(args, "s") {
                    self.search_deletes(unit, &targets);
                }
            }
            "rd" | "rmdir" if shell == Shell::Cmd && has_switch(args, "s") => {
                let targets = builtin(key, args);
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
                let (sources, destination) =
                    sources_and_destination(args, &["-S", "--suffix"], shell);
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
                if let (sources, Some(destination)) =
                    sources_and_destination(args, &COPY_VALUED, shell)
                {
                    let leaves = leaves(unit, &sources);
                    self.copy_to(shell, unit.scope(), &leaves, &destination, recursive);
                }
            }
            "ln" if shell != Shell::PowerShell => {
                // A link reaches its target through a name inside the
                // workspace, so a later write or delete of the link lands on
                // whatever it points at.
                let (sources, destination) =
                    sources_and_destination(args, &["-S", "--suffix"], shell);
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
                // `xcopy /exclude:list.txt` names a file of strings to skip,
                // which it reads: no operand.
                let kept: Vec<Arg> = args
                    .iter()
                    .filter(|arg| key != "xcopy" || !valued(arg, &["exclude"]))
                    .cloned()
                    .collect();
                let operands = builtin(key, &kept);
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
                // A log or a job file it writes, and a job file it reads, are
                // switches with a value, not folders or files to copy.
                // A value known only when it runs (`/LOG:%X%`) is a write to
                // a place known only then.
                for arg in args {
                    let Some(text) = written(arg) else {
                        continue;
                    };
                    let text = text.as_ref();
                    let known = arg.known().is_some();
                    let file = |value: String| {
                        if known {
                            Arg::Known(value)
                        } else {
                            Arg::Unknown(value)
                        }
                    };
                    if let Some(value) = switch_value(text, &ROBOCOPY_LOGS) {
                        let log = file(value.to_string());
                        self.write(shell, unit.scope(), &log, "writes a log to");
                    }
                    if let Some(value) = switch_value(text, &["save"]) {
                        let job = file(format!("{value}.rcj"));
                        self.write(shell, unit.scope(), &job, "writes to");
                    }
                }
                // A job file holds folders and switches of its own, which the
                // guard never sees.
                if let Some(job) = args.iter().find(|arg| valued(arg, &["job"])) {
                    self.add(
                        Rule::Unknown,
                        "copies by a job file the guard does not read",
                        Some(job),
                    );
                }
                let operands: Vec<&Arg> = plain(args)
                    .into_iter()
                    .filter(|arg| !valued(arg, &ROBOCOPY_LOGS) && !valued(arg, &["save", "job"]))
                    .collect();
                if let Some(destination) = operands.get(1) {
                    let flagged = Flagged::of(
                        has_switch(args, "mir") || has_switch(args, "purge"),
                        unread_option(args, shell),
                    );
                    self.flagged(flagged, |checker| {
                        checker.delete(unit, &[destination], "deletes files in");
                    });
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
                // `--remove-source-files` deletes each file it has sent, on
                // this machine or on the one a source is on.
                if operands.len() >= 2
                    && args.iter().any(|arg| {
                        matches!(
                            arg.known(),
                            Some("--remove-source-files" | "--remove-sent-files")
                        )
                    })
                {
                    let sources = &operands[..operands.len() - 1];
                    let (away, here): (Vec<&Arg>, Vec<&Arg>) =
                        sources.iter().copied().partition(|source| remote(source));
                    for source in away {
                        self.add(
                            Rule::Delete,
                            "deletes files on another machine",
                            Some(source),
                        );
                    }
                    self.delete(unit, &here, "deletes");
                }
                if operands.len() >= 2 {
                    if let Some(destination) =
                        operands.last().filter(|destination| !remote(destination))
                    {
                        let flagged = Flagged::of(
                            args.iter().any(|arg| {
                                arg.known().is_some_and(|text| text.starts_with("--delete"))
                            }),
                            may_be_option(args, shell, |start| {
                                could_be(start, None, Some("delete"))
                                    || start.starts_with("--delete")
                            }),
                        );
                        self.flagged(flagged, |checker| {
                            checker.delete(unit, &[destination], "deletes files in");
                        });
                        let recursive = has_flag(args, Some('r'), Some("recursive"))
                            || has_flag(args, Some('a'), Some("archive"));
                        let sources = &operands[..operands.len() - 1];
                        let leaves = leaves(unit, sources);
                        self.copy_to(shell, unit.scope(), &leaves, destination, recursive);
                    }
                }
            }
            "copy-item" | "move-item" => self.copy_item(unit, key),

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
                // Every path and positional is the item or the new name; a
                // new name made at run time (`$name`, `($a + 'x')`) after
                // the first positional is not a place of the item, unless the
                // guard cannot tell which is which: a bare `-n` (read as a
                // switch, it leaves its value among the positionals), a
                // `--`, or a splat (`@p` may bind `-Path` or `-NewName`).
                let doubtful =
                    params.named.iter().any(|(name, value)| {
                        value.is_none() && "newname".starts_with(name.as_str())
                    }) || params
                        .positional
                        .iter()
                        .any(|arg| arg.known() == Some("--"))
                        || splatted(args);
                // What is renamed away is judged as the items the cmdlet
                // works on: a path, else what the stage before lists.
                let mut paths = params.values(&["path", "literalpath"]);
                paths.extend(
                    without_dashes(&params)
                        .into_iter()
                        .enumerate()
                        .filter(|(at, arg)| *at == 0 || doubtful || arg.known().is_some())
                        .map(|(_, arg)| arg),
                );
                let items = self.listed_paths(unit, paths);
                self.move_away(unit, &items.iter().collect::<Vec<_>>(), "renames");
                let mut sources = params.values(&["path", "literalpath"]);
                let mut positional = without_dashes(&params).into_iter();
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
                    self.write_as(shell, unit.scope(), name, "renames to", Access::Item);
                }
            }
            "ren" | "rename" if shell == Shell::Cmd => {
                let operands = builtin(key, args);
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
                if let [link, target, ..] = taken(key, args).as_slice() {
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
                for target in self.list_items(unit, &Params::read(args)) {
                    self.write_as(shell, unit.scope(), &target, verb, Access::Item);
                }
            }

            // Unpacking an archive writes into the folder it unpacks to;
            // packing one with `--remove-files`, `-m` or `-sdel` deletes
            // what it packs, as `rar m` does.
            "tar" | "gtar" | "bsdtar" | "7z" | "7za" | "7zr" | "7zz" => {
                self.unpack(unit, key);
                self.pack_and_remove(unit, key);
            }
            "unzip" | "expand-archive" | "cpio" | "gcpio" | "bsdcpio" | "ditto" | "pax"
            | "unrar" | "unar" | "jar" | "py" => self.unpack(unit, key),
            _ if key.starts_with("python") => self.unpack(unit, key),
            "rar" => {
                self.unpack(unit, key);
                self.pack_and_remove(unit, key);
            }
            "zip" => self.pack_and_remove(unit, key),

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
                for target in taken(key, args) {
                    self.make_folder(shell, unit.scope(), target, Access::Content);
                }
            }
            "sed" => {
                let flagged = flagged(args, shell, Some('i'), Some("in-place"));
                self.flagged(flagged, |checker| {
                    for file in sed_files(args) {
                        checker.write(shell, unit.scope(), file, "edits");
                    }
                });
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
                if targets.is_empty() && key == "new-item" {
                    // Only `-Path` is positional, so with no `-Path` named
                    // every positional is judged (an extra one only makes
                    // the command fail), and a bare `-n` (`-Name`), a `--`
                    // or a `-Type` cannot hide the path behind another
                    // argument.
                    targets.extend(without_dashes(&params).into_iter().cloned());
                } else if targets.is_empty() {
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
                let params = Params::read_property(args);
                let mut targets = params.values(&["path", "literalpath"]);
                // The first positional and every known one are judged; every
                // positional when the guard cannot tell which is the path: a
                // bare named parameter that may take a value (`-n`, read as
                // a switch, leaves its value among the positionals), a `--`
                // or a splat (`@p` may bind `-Path`).
                let doubtful = params.unclear()
                    || params
                        .positional
                        .iter()
                        .any(|arg| arg.known() == Some("--"))
                    || splatted(args);
                targets.extend(
                    without_dashes(&params)
                        .into_iter()
                        .enumerate()
                        .filter(|(at, arg)| *at == 0 || doubtful || arg.known().is_some())
                        .map(|(_, arg)| arg),
                );
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
            // An output only known when it runs may be a disk: an unknown
            // output of `cp` is a write, and one of `dd` writes over a disk.
            "dd" => {
                for file in dd_outputs(args, shell) {
                    let place = self.place_into(shell, unit.scope(), &file, Access::Content);
                    if file.known().is_some() && place != Place::Unknown {
                        self.write(shell, unit.scope(), &file, "writes to");
                    } else {
                        self.add(
                            Rule::WipeDisk,
                            "writes over a disk or file only known when it runs",
                            Some(&file),
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

    /// `del /s` from the workspace folder: it deletes the files of every folder
    /// below it that its name pattern matches, and takes `.git`'s own files
    /// (`HEAD`, `config`, `index`, ...) when the pattern can match one. cmd
    /// is taken to search hidden folders too: not checked on Windows, and a
    /// false safe is the worse mistake. A pattern deeper in the workspace is
    /// the agent's, as `.git` there is not the model's to protect.
    fn search_deletes(&mut self, unit: &Unit, targets: &[Arg]) {
        for target in targets {
            let Arg::Known(text) = target else {
                continue;
            };
            let at = text.rfind(['/', '\\', ':']).map_or(0, |at| at + 1);
            // cmd reads no wildcard in a folder part (`*\x`): the resolver
            // judges the whole path. The `?` of a long-path prefix
            // (`\\?\C:\...`) is not a wildcard.
            let folder_text = &text[..at];
            if glob::has_wildcard(verbatim(folder_text).unwrap_or(folder_text)) {
                continue;
            }
            let reaches = glob::can_match_git_entry(&text[at..], Flavour::Windows);
            let folder = Arg::Known(folder_of(&text[..at]));
            if reaches
                && matches!(
                    self.place(unit.shell, unit.scope(), &folder, Access::Item),
                    Place::Workspace { exact: true }
                )
            {
                self.add(
                    Rule::Delete,
                    "deletes files in every folder below the workspace, the repository's history among them",
                    Some(target),
                );
            }
        }
    }
}

/// Whether an argument is a splat (`@p`, `@args`): a hashtable of parameters
/// only known when it runs, which may bind any parameter, a path among them.
/// `@(...)`, `@{...}`, `@'...'` and `@"..."` are arrays, hashtables and
/// strings, not splats.
fn is_splat(arg: &Arg) -> bool {
    matches!(arg, Arg::Unknown(text)
        if text.strip_prefix('@')
            .is_some_and(|name| name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')))
}

/// Whether any argument is a splat.
fn splatted(args: &[Arg]) -> bool {
    args.iter().any(is_splat)
}

/// The positionals, without a `--` (the end of the parameters, not a path).
fn without_dashes<'a>(params: &Params<'a>) -> Vec<&'a Arg> {
    params
        .positional
        .iter()
        .copied()
        .filter(|arg| arg.known() != Some("--"))
        .collect()
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
        // Many items of one folder land on the same name: each is judged once.
        let mut seen = HashSet::new();
        for source in sources {
            let (found, _) = self.expand(unit, source);
            for from in found {
                let to = renamed(&from, name);
                if seen.insert((to.known().is_some(), to.text().to_string())) {
                    self.write_as(unit.shell, unit.scope(), &to, "writes to", Access::Item);
                }
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

/// The switches of `robocopy` that name a log file it writes: `/LOG+:` and
/// `/UNILOG+:` add to it, the others replace it.
const ROBOCOPY_LOGS: [&str; 4] = ["log", "log+", "unilog", "unilog+"];

/// Whether `arg` is a `/NAME:value` switch with one of `names`, its value
/// known or only known when it runs (`/LOG:%X%`).
fn valued(arg: &Arg, names: &[&str]) -> bool {
    written(arg).is_some_and(|text| switch_value(&text, names).is_some())
}

/// The text of `arg` as the program reads a switch: its value, or, for one
/// known only when it runs, its text with each expansion as written and
/// without the quotes a program never sees (`/LOG:%X%`, `"/LOG:%X%"`).
/// `None` for the input of a pipeline and `$null`.
fn written(arg: &Arg) -> Option<Cow<'_, str>> {
    match arg {
        Arg::Known(text) => Some(Cow::Borrowed(text)),
        Arg::Unknown(text) | Arg::Template { text, .. } => Some(Cow::Owned(text.replace('"', ""))),
        Arg::Input | Arg::Null => None,
    }
}

/// Whether `text` is a switch `program`, one of cmd's built-in commands or
/// `xcopy`, takes: a switch by its shape (see [`crate::unit::is_switch`]) whose every name
/// is one of the program's. cmd's built-ins never read a quoted word as a
/// switch, and the quotes are gone by here, so `rd /s /q "/Users"` names the
/// folder `\Users`: a name the program does not take is a path, judged
/// where it lands (`del /Users` is no switch either, only an error).
fn takes(program: &str, text: &str) -> bool {
    let names: &[&str] = match program {
        "del" | "erase" => &["p", "f", "s", "q"],
        "rd" | "rmdir" => &["s", "q"],
        "copy" => &["a", "b", "d", "v", "n", "y", "-y", "z", "l"],
        "move" => &["y", "-y"],
        "mklink" => &["d", "h", "j"],
        "xcopy" => &[
            "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
            "r", "s", "t", "u", "v", "w", "x", "y", "-y", "z", "exclude", "compress",
        ],
        _ => &[],
    };
    switch_names(text).is_some_and(|run| {
        run.iter().all(|name| {
            let name = name.to_ascii_lowercase();
            names.contains(&name.as_str())
                // `del /a`, `/ah`, `/a-h`: the attributes of the files to
                // delete.
                || (matches!(program, "del" | "erase")
                    && name
                        .strip_prefix('a')
                        .is_some_and(|rest| rest.chars().all(|c| "rhsailo-".contains(c))))
        })
    })
}

/// The arguments of `program` that are not switches it takes (see
/// [`takes`]).
fn taken<'a>(program: &str, args: &'a [Arg]) -> Vec<&'a Arg> {
    args.iter()
        .filter(|arg| !arg.known().is_some_and(|text| takes(program, text)))
        .collect()
}

/// The operands of cmd's built-in commands (`del`, `rd`, `copy`, `move`),
/// which also end an argument at `,`, `;` and `=`: `rd /s /q x,C:\Users\me`
/// is two folders. Each part is a switch `program` takes (see [`takes`]) or
/// an operand of its own, so `/q;//evil/s` is the switch `/q` and a share.
fn builtin(program: &str, args: &[Arg]) -> Vec<Arg> {
    args.iter()
        .flat_map(|arg| match arg {
            Arg::Known(text) => text
                .split([',', ';', '='])
                .filter(|part| !part.is_empty())
                .map(|part| Arg::Known(part.to_string()))
                .collect::<Vec<_>>(),
            other => vec![other.clone()],
        })
        .filter(|arg| !arg.known().is_some_and(|text| takes(program, text)))
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

/// The folder a `del` pattern is searched from, given what comes before the
/// pattern's name: `.` for none, the text without its last separator, and the
/// root of a drive (`C:\`) or a drive's own folder (`C:`) as written.
fn folder_of(before: &str) -> String {
    match before {
        "" => ".".to_string(),
        text if text.ends_with(':') => text.to_string(),
        text => {
            let trimmed = &text[..text.len() - 1];
            if trimmed.is_empty() || trimmed.ends_with(':') {
                text.to_string()
            } else {
                trimmed.to_string()
            }
        }
    }
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

impl Checker<'_> {
    /// `Copy-Item` and `Move-Item`. `-Path` is position 0 and `-Destination`
    /// position 1. A comma list of sources is flattened into the arguments,
    /// so an operand after the first destination may be one more source:
    /// each is read as the destination in turn, with the rest as sources,
    /// and a risky reading wins.
    ///
    /// The work is linear in the operands, not in the readings: readings
    /// whose destinations are spelt the same have the same sources, so each
    /// is read once; the names of the sources are taken once each; and the
    /// files moved are every operand. What is left is each destination with
    /// each name: a line that gives more than [`MAX_ITEM_PAIRS`] of those is
    /// unreadable.
    fn copy_item(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let shell = unit.shell;
        let params = Params::read(args);
        let paths = params.values(&["path", "literalpath"]);
        let recursive = key == "copy-item"
            && params
                .named
                .iter()
                .any(|(name, _)| "recurse".starts_with(name.as_str()));
        let mut operands = paths.clone();
        operands.extend(params.positional.iter().copied());
        let destination = params.values(&["destination"]).first().copied();
        // A splat (`@p`) with no `-Destination` named may bind it: it is
        // judged as a place too, beside a destination that is known
        // (`Copy-Item @p src\a`, where `@p` may be the `-Destination` and
        // `src\a` the `-Path`).
        if destination.is_none() && splatted(args) {
            for splat in params
                .positional
                .iter()
                .copied()
                .filter(|arg| is_splat(arg))
            {
                self.write_as(shell, unit.scope(), splat, "writes to", Access::Item);
            }
        }
        if let Some(destination) = destination {
            // What the pipeline hands it is a source too.
            if operands.is_empty() && from_pipe(unit) {
                operands.push(&Arg::Input);
            }
            if key == "move-item" {
                let moved: Vec<&Arg> = operands
                    .iter()
                    .copied()
                    .filter(|source| **source != Arg::Input)
                    .collect();
                self.moved_items(unit, &params, &moved);
            }
            let leaves = leaves(unit, &operands);
            // A `$null` destination is no destination: the item goes to the
            // folder the line is in.
            let destination = or_here(destination);
            self.copy_to(shell, unit.scope(), &leaves, &destination, recursive);
            return;
        }
        let first = paths.len().max(1);
        if key == "move-item" {
            // Each operand is a source of some reading when there are two
            // readings or more, and with one, all but its destination are.
            let moved: Vec<&Arg> = match operands.len().saturating_sub(first) {
                0 => Vec::new(),
                1 => operands[..operands.len() - 1].to_vec(),
                _ => operands.clone(),
            };
            let moved: Vec<&Arg> = moved
                .into_iter()
                .filter(|source| **source != Arg::Input)
                .collect();
            self.moved_items(unit, &params, &moved);
        }
        // The names each operand lands at, and how many operands give each.
        let own: Vec<Vec<String>> = operands
            .iter()
            .map(|operand| leaves(unit, &[operand]))
            .collect();
        let mut given: HashMap<&str, usize> = HashMap::new();
        let mut order: Vec<&str> = Vec::new();
        for leaf in own.iter().flatten() {
            let count = given.entry(leaf.as_str()).or_insert(0);
            if *count == 0 {
                order.push(leaf.as_str());
            }
            *count += 1;
        }
        let total: usize = own.iter().map(Vec::len).sum();
        let mut read: HashSet<&Arg> = HashSet::new();
        let destinations = (first..operands.len()).filter(|at| read.insert(operands[*at]));
        let destinations: Vec<usize> = destinations.collect();
        if destinations.len().saturating_mul(order.len()) > MAX_ITEM_PAIRS {
            self.add(Rule::Unreadable, "names too many paths to read", None);
            return;
        }
        for at in destinations {
            // The sources are every operand but this one: its own names
            // count only where another operand gives them too.
            let mine = &own[at];
            let leaves: Vec<&str> = order
                .iter()
                .copied()
                .filter(|leaf| {
                    let theirs = mine.iter().filter(|own| own.as_str() == *leaf).count();
                    given.get(leaf).copied().unwrap_or(0) > theirs
                })
                .collect();
            let several = total - mine.len() > 1;
            let destination = or_here(operands[at]);
            self.copy_into(
                shell,
                unit.scope(),
                (&leaves, several),
                &destination,
                recursive,
            );
        }
    }

    /// What `Move-Item` moves away: `moved`, or with none, what the stage
    /// before lists.
    fn moved_items(&mut self, unit: &Unit, params: &Params<'_>, moved: &[&Arg]) {
        let piped = if moved.is_empty() {
            self.items(unit, params)
        } else {
            Vec::new()
        };
        let mut moved = moved.to_vec();
        moved.extend(piped.iter());
        self.move_away(unit, &moved, "moves");
    }
}

/// The most pairs of a destination and a name that a `Copy-Item` or
/// `Move-Item` is read for (see [`Checker::copy_item`]): 64 different paths,
/// each the destination of the 63 others. A real comma list of sources gives
/// a few; a line that names thousands of different ones is noise, and
/// reading each with each would take seconds.
const MAX_ITEM_PAIRS: usize = 64 * 64;
