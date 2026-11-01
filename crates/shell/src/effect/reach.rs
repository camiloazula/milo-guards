//! Where the reads of a line land, for [`super::Reach`].
//!
//! A line reads what its file operands name, the source of each `<`
//! redirect, the folder a lister lists, and the working directory when a
//! reader with no file operand reads it without being told (`ls`, `rg TODO`,
//! `git status`). `effect` already places each of the first two to judge
//! them, so saying where they land costs nothing more; the rest is read here.
//!
//! Every place is judged by where core says it lands. It is harmless when it
//! is inside a workspace folder, a temporary file or the null device, and the
//! workspace folder itself (what `ls` lists at the project's root). Anything
//! else, a protected path included, is beyond. A reader this module does not
//! know to read only its operands is taken to read the working directory too:
//! what cannot be placed is never the workspace.

use milo_guards_core::spelling::glob;
use milo_guards_core::Paths;

use super::operands::{shape, takes_no_paths, Context, Opened};
use super::Kind;
use crate::path::{self, Place, Resolver};
use crate::unit::{moves_to, Arg, Unit};
use crate::Shell;

/// Where the reads of a line landed, as the units were judged.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Lands {
    /// A read landed where it is not harmless.
    beyond: bool,
    /// A read landed on a workspace folder itself, which is harmless unless
    /// something in it is protected and the line reads all of it.
    root: bool,
    /// A read took every file below the folders it names, whatever they hold
    /// (`rg TODO`, `grep -r`, what `find` lists handed to `xargs cat`).
    deep: bool,
}

impl Context<'_> {
    /// Record a read that lands at `place`.
    pub(super) fn land(&self, place: Place) {
        let mut lands = self.lands.get();
        match place {
            Place::Workspace { exact: true } => lands.root = true,
            place if place.harmless() => {}
            _ => lands.beyond = true,
        }
        self.lands.set(lands);
    }

    /// Record a read that lands somewhere the guard cannot name.
    fn far(&self) {
        let mut lands = self.lands.get();
        lands.beyond = true;
        self.lands.set(lands);
    }

    /// Record a read of everything below the folders it names.
    pub(super) fn deepen(&self) {
        let mut lands = self.lands.get();
        lands.deep = true;
        self.lands.set(lands);
    }

    /// Record a read of `text`, written from the folder `unit` runs in.
    fn land_text(&self, unit: &Unit, text: &str) {
        let from = path::within(unit.dir.as_ref(), &Arg::Known(text.to_string()), unit.shell);
        self.land(self.resolver.place(&from, unit.shell, unit.hidden));
    }
}

/// What `unit`, a reader of its operands, also reads: the working directory
/// when nothing tells it where to look, and what its arguments name that the
/// table does not call a place. `Unknown` when the working directory itself
/// is not known (after a `cd` the guard cannot follow).
pub(super) fn reads(unit: &Unit, key: &str, opened: &Opened<'_>, context: &Context<'_>) -> Kind {
    // A `cd` reads its target, which `judge_unit` placed.
    if moves_to(unit).is_some() {
        return Kind::Reads;
    }
    let mut kind = Kind::Reads;
    if implicit(unit, key, opened) {
        kind = here(unit, context);
    }
    // `git -C a -C b` reads the repository at `a/b`: each folder is relative
    // to the one before it, and an absolute one starts over.
    if key == "git" && !opened.dirs.is_empty() {
        let mut dir = unit.dir.clone();
        for next in &opened.dirs {
            dir = Some(path::within(dir.as_ref(), next, unit.shell));
        }
        if let Some(dir) = dir {
            context.land(context.resolver.place(&dir, unit.shell, false));
        }
    }
    // A wildcard in PowerShell or cmd is the program's own, and can go below
    // the folder it starts in: that folder is read, whatever the pattern
    // lands on.
    if unit.shell != Shell::Posix {
        for text in opened.places.iter().filter_map(|place| place.known()) {
            if glob::has_wildcard(text) {
                context.land_text(unit, &folder_of(text));
            }
        }
    }
    // `df` with no operand reports every disk that is mounted.
    if unit.shell == Shell::Posix && key == "df" && opened.operands == 0 {
        context.far();
    }
    if deepens(unit, key) {
        context.deepen();
    }
    // `echo ~/.ssh/*` opens nothing, but the shell lists the folder.
    if unit.shell == Shell::Posix && takes_no_paths(unit.shell, key) {
        for text in unit.args.iter().filter_map(Arg::known) {
            if glob::has_wildcard(text) {
                context.land_text(unit, text);
            }
        }
    }
    // `find -newer FILE` reads the file's time.
    if unit.shell == Shell::Posix && key == "find" {
        let mut args = unit.args.iter().filter_map(Arg::known);
        while let Some(text) = args.next() {
            if text.starts_with("-newer") || matches!(text, "-anewer" | "-cnewer" | "-samefile") {
                if let Some(file) = args.next() {
                    context.land_text(unit, file);
                }
            }
        }
    }
    // A revision or a pathspec is read inside the repository; the part of
    // `HEAD:path` after the colon is a path in it.
    for spec in &opened.pathspecs {
        if let Some(text) = spec.known() {
            context.land_text(unit, text);
            if let Some((_, path)) = text.split_once(':') {
                context.land_text(unit, path);
            }
        }
    }
    kind
}

/// The folder a pattern starts in: what comes before its first wildcard,
/// up to the last separator before it.
fn folder_of(text: &str) -> String {
    let wild = text.find(['*', '?', '[']).unwrap_or(text.len());
    match text[..wild].rfind(['/', '\\']) {
        Some(0) => text[..1].to_string(),
        Some(at) => text[..at].to_string(),
        None => ".".to_string(),
    }
}

/// Where the working directory is, as a read: `Unknown` when a `cd` moved
/// it somewhere the guard cannot name.
fn here(unit: &Unit, context: &Context<'_>) -> Kind {
    let dot = Arg::Known(".".to_string());
    let from = path::within(unit.dir.as_ref(), &dot, unit.shell);
    let place = context.resolver.place(&from, unit.shell, false);
    context.land(place);
    if matches!(place, Place::Unknown) {
        Kind::Unknown
    } else {
        Kind::Reads
    }
}

/// Whether the reader reads the working directory without being told to:
/// every reader that is not known to read only its operands or its input
/// does, when it is given no operand to read. `git` reads the repository at
/// the working directory, or at `-C`.
fn implicit(unit: &Unit, key: &str, opened: &Opened<'_>) -> bool {
    if key == "git" {
        return opened.dirs.is_empty();
    }
    if takes_no_paths(unit.shell, key) {
        return false;
    }
    let bare = opened.operands == 0;
    match unit.shell {
        Shell::Posix => match key {
            "cat" | "head" | "tail" | "wc" | "stat" | "realpath" | "diff" | "sort" | "file"
            | "less" | "df" => false,
            "grep" | "egrep" | "fgrep" => bare && recursive(&unit.args),
            _ => bare,
        },
        Shell::PowerShell => match key {
            "get-content" | "cat" | "gc" | "type" | "select-string" | "sls" | "get-item"
            | "test-path" | "resolve-path" => false,
            _ => bare,
        },
        Shell::Cmd => match key {
            "type" | "findstr" => false,
            _ => bare,
        },
    }
}

/// Whether a `grep` is given a flag that makes it search folders (`-r`,
/// `-R`, `-d`, `--recursive`, `--directories`), or an argument that could be
/// one because it is known only when it runs.
fn recursive(args: &[Arg]) -> bool {
    args.iter().any(|arg| match shape(arg) {
        None => true,
        Some((head, tail)) => match head.strip_prefix("--") {
            Some(long) => {
                long.starts_with("recursive")
                    || long.starts_with("dereference-recursive")
                    || long.starts_with("directories")
            }
            None => match head.strip_prefix('-') {
                Some(bundle) => bundle.contains(['r', 'R', 'd']),
                None => head.is_empty() && tail,
            },
        },
    })
}

/// Whether the unit reads every file below the folders it names.
fn deepens(unit: &Unit, key: &str) -> bool {
    let known = || unit.args.iter().filter_map(Arg::known);
    match (unit.shell, key) {
        (Shell::Posix, "rg") => true,
        (Shell::Posix, "grep" | "egrep" | "fgrep") => recursive(&unit.args),
        // What `-exec` runs reads what `find` found, which is everything
        // below its start.
        (Shell::Posix, "find") => {
            known().any(|text| matches!(text, "-exec" | "-execdir" | "-ok" | "-okdir"))
        }
        // `findstr /s` goes into every folder below.
        (Shell::Cmd, "findstr") => known().any(|text| {
            text.starts_with(['/', '-'])
                && text[1..]
                    .split(':')
                    .next()
                    .is_some_and(|names| names.to_ascii_lowercase().contains('s'))
        }),
        _ => false,
    }
}

/// Whether the line reached beyond the workspace: a read landed where it is
/// not harmless, or it read everything below a workspace folder that holds a
/// protected path.
pub(super) fn beyond(context: &Context<'_>, paths: &Paths) -> bool {
    let lands = context.lands.get();
    lands.beyond || (lands.deep && lands.root && holds_protected(context.resolver, paths))
}

/// Whether a protected path sits inside a workspace folder: some folder
/// above it is a workspace folder itself. Read by the spelling of both
/// flavours, since a line is judged by one shell and the paths are the
/// caller's.
fn holds_protected(resolver: &Resolver, paths: &Paths) -> bool {
    paths.protected.iter().any(|entry| {
        let text = entry.path.to_string_lossy();
        let mut above: &str = &text;
        while let Some(at) = above.rfind(['/', '\\']) {
            above = &above[..at];
            if above.is_empty() {
                break;
            }
            let folder = Arg::Known(above.to_string());
            for shell in [Shell::Posix, Shell::Cmd] {
                if resolver.place(&folder, shell, false) == (Place::Workspace { exact: true }) {
                    return true;
                }
            }
        }
        false
    })
}
