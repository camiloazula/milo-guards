//! The rules about files: what a line deletes, moves, copies and writes.

use super::{downloads_to, sources_and_destination, Checker};
use crate::launch::{find_targets, perl_edits};
use crate::path::Place;
use crate::powershell::Params;
use crate::unit::{has_flag, has_switch, operands, plain, Arg, Unit};
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
                    self.write(shell, unit.scope(), &destination, "writes to");
                }
            }
            "cp" | "install" if shell != Shell::PowerShell => {
                if let (_, Some(destination)) = sources_and_destination(
                    args,
                    &[
                        "-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g", "--group",
                    ],
                ) {
                    self.write(shell, unit.scope(), &destination, "writes to");
                }
            }
            "ln" if shell != Shell::PowerShell => {
                // A link reaches its target through a name inside the
                // workspace, so a later write or delete of the link lands on
                // whatever it points at.
                let (sources, destination) = sources_and_destination(args, &["-S", "--suffix"]);
                for source in &sources {
                    let place = self.place(shell, unit.scope(), source);
                    if !place.harmless() && !matches!(place, Place::Workspace { exact: true }) {
                        self.add(
                            Rule::Overwrite,
                            format!("links to {}", place.words()),
                            Some(source),
                        );
                    }
                }
                if let Some(destination) = destination {
                    self.write(shell, unit.scope(), &destination, "writes to");
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
                        self.write(shell, unit.scope(), destination, "writes to");
                    }
                }
            }
            "robocopy" => {
                let operands = plain(args);
                if let Some(destination) = operands.get(1) {
                    if has_switch(args, "mir") || has_switch(args, "purge") {
                        self.delete(unit, &[destination], "deletes files in");
                    }
                    self.write(shell, unit.scope(), destination, "writes to");
                }
            }
            "rsync" => {
                let operands = operands(
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
                );
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
                        self.write(shell, unit.scope(), destination, "writes to");
                    }
                }
            }
            "copy-item" | "move-item" => {
                let params = Params::read(args);
                let mut positional = params.positional.clone();
                let mut sources = params.values(&["path", "literalpath"]);
                // `-Destination`, else the last positional after the path:
                // one that is the only positional and no `-Path` is the path.
                let destination_unnamed = params.values(&["destination"]).is_empty();
                let destination = if let Some(named) = params.values(&["destination"]).first() {
                    Some(*named)
                } else if sources.is_empty() && positional.len() < 2 {
                    None
                } else {
                    positional.pop()
                };
                // A splat (`@p`) with no `-Destination` named may bind it:
                // it is judged as a place too, beside a destination that is
                // known (`Copy-Item @p src\a`, where `@p` may be the
                // `-Destination` and `src\a` the `-Path`).
                if destination_unnamed && splatted(args) {
                    for splat in
                        positional.iter().copied().chain(destination).filter(
                            |arg| matches!(arg, Arg::Unknown(text) if text.starts_with('@')),
                        )
                    {
                        self.write(shell, unit.scope(), splat, "writes to");
                    }
                }
                // Every other positional is a source too (`Move-Item a, b
                // -Destination d`; a comma list is read as separate ones).
                sources.extend(positional);
                if key == "move-item" {
                    // With no path, what the stage before lists is moved.
                    let moved = self.listed_paths(unit, sources);
                    self.move_away(unit, &moved.iter().collect::<Vec<_>>(), "moves");
                }
                if let Some(destination) = destination {
                    self.write(shell, unit.scope(), destination, "writes to");
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
                    self.write(shell, unit.scope(), &target, verb);
                }
            }
            "rename-item" => {
                let params = Params::read(args);
                // Every path and positional is the item or the new name; a
                // new name made at run time (`$name`, `($a + 'x')`) after
                // the first positional is not a place, unless the guard
                // cannot tell which is which: a bare `-n` (read as a switch,
                // it leaves its value among the positionals), a `--`, or a
                // splat (`@p` may bind `-Path` or `-NewName`).
                let doubtful =
                    params.named.iter().any(|(name, value)| {
                        value.is_none() && "newname".starts_with(name.as_str())
                    }) || params
                        .positional
                        .iter()
                        .any(|arg| arg.known() == Some("--"))
                        || splatted(args);
                let mut paths = params.values(&["path", "literalpath"]);
                paths.extend(
                    params
                        .positional
                        .iter()
                        .filter(|arg| arg.known() != Some("--"))
                        .enumerate()
                        .filter(|(at, arg)| *at == 0 || doubtful || arg.known().is_some())
                        .map(|(_, arg)| *arg),
                );
                let items = self.listed_paths(unit, paths);
                self.move_away(unit, &items.iter().collect::<Vec<_>>(), "renames");
                // The new name is a name, not a path; one that holds a
                // separator is a place the item is moved to.
                for name in params.values(&["newname"]) {
                    if name
                        .known()
                        .is_some_and(|name| name.contains(['\\', '/', ':']))
                    {
                        self.write(shell, unit.scope(), name, "renames to");
                    }
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
                    self.write(shell, unit.scope(), target, "creates");
                }
            }
            "md" if shell == Shell::Cmd => {
                for target in plain(args) {
                    self.write(shell, unit.scope(), target, "creates");
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
                let params = Params::read(args);
                let mut targets = params.values(&["path", "literalpath", "filepath"]);
                if targets.is_empty() {
                    targets.extend(params.positional.first().copied());
                }
                let verb = if key == "clear-content" {
                    "empties"
                } else {
                    "writes to"
                };
                for target in targets {
                    self.write(shell, unit.scope(), target, verb);
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
                // A splat may bind `-Path` to any argument's place, so the
                // first positional is not known to be the path.
                if splatted(args) {
                    targets.extend(params.positional.iter().copied());
                }
                for target in targets {
                    self.write(shell, unit.scope(), target, "changes");
                }
            }
            // A value moved or copied between keys: the path, the destination and
            // any argument that may stand for either are judged.
            "copy-itemproperty" | "move-itemproperty" => {
                let params = Params::read(args);
                let mut targets = params.values(&["path", "literalpath", "destination"]);
                targets.extend(params.positional.iter().copied());
                for target in targets {
                    self.write(shell, unit.scope(), target, "changes");
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

/// Whether an argument is a splat (`@p`): a hashtable of parameters only
/// known when it runs, which may bind any parameter, a path among them.
fn splatted(args: &[Arg]) -> bool {
    args.iter()
        .any(|arg| matches!(arg, Arg::Unknown(text) if text.starts_with('@')))
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

/// An rsync `host:path` destination, which is not on this machine.
fn remote(arg: &Arg) -> bool {
    arg.known().is_some_and(|text| {
        text.find(':')
            .is_some_and(|colon| colon > 1 && !text[..colon].contains('/'))
    })
}
