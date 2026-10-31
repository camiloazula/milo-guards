//! The rules about files: what a line deletes, moves, copies and writes.

use super::{downloads_to, or_here, sources_and_destination, Checker};
use crate::launch::{find_targets, perl_edits};
use crate::path::{Access, Place};
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
                self.move_away(unit, &sources);
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
                    let place = self.place(shell, unit.scope(), source, Access::Item);
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
                    self.move_away(unit, &operands[..operands.len() - 1]);
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
                if sources.is_empty() && !positional.is_empty() {
                    sources.push(positional.remove(0));
                }
                if key == "move-item" {
                    self.move_away(unit, &sources);
                }
                if let Some(destination) = params
                    .values(&["destination"])
                    .first()
                    .or(positional.first())
                {
                    // A `$null` destination is no destination: the item goes
                    // to the folder the line is in. In the registry the
                    // destination is a key, so it is an item.
                    let destination = or_here(destination);
                    self.write_as(shell, unit.scope(), &destination, "writes to", Access::Item);
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
                let mut targets: Vec<Arg> = targets.into_iter().cloned().collect();
                if key == "new-item" {
                    // With `-Name` the path is optional: no path, or a `$null`
                    // one, makes the item in the folder the line is in.
                    targets = targets.iter().map(or_here).collect();
                    if targets.is_empty() {
                        targets.push(Arg::Known(".".to_string()));
                    }
                }
                for target in &targets {
                    self.write_as(shell, unit.scope(), target, verb, access);
                }
            }
            "set-itemproperty" | "new-itemproperty" | "remove-itemproperty" => {
                let params = Params::read(args);
                let mut targets = params.values(&["path", "literalpath"]);
                if targets.is_empty() {
                    targets.extend(params.positional.first().copied());
                }
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
