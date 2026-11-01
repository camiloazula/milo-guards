//! Where the reads of a line land, for [`super::Reach`].
//!
//! A line reads what its file operands name, the source of each `<`
//! redirect, the folder a lister lists, and the working directory when a
//! reader with no file operand reads it without being told (`ls`, `rg TODO`,
//! `git status`). `effect` already places each of the first two to judge
//! them, so saying where they land costs nothing more; the rest is read here.
//!
//! `Reach` is about reading what is not the project's. A read is `Beyond`
//! when its place is beyond the workspace (the home folder, a system folder,
//! another folder of the disk), or when it is a secret ([`Sensitivity::Secret`]:
//! a key, a credential) even inside the workspace. The repository's own
//! history, a startup file and the caller's protected paths are inside the
//! workspace when they are, and stay `Workspace`: protecting them is about
//! writes. What cannot be placed is `Beyond`, never the workspace.
//!
//! A reader that goes below the folders it names (a recursive search, a
//! listing of every name) reaches whatever is below them: it is deep, and a
//! deep read of a folder that holds a secret is `Beyond`. A reader is shallow
//! only when its table entry says so for the flags it is given; anything
//! recursive or unknown is deep. A wildcard is judged by what it can pick.

use milo_guards_core::spelling::glob;
use milo_guards_core::Sensitivity;

use super::operands::{shape, takes_no_paths, Context, Opened};
use super::Kind;
use crate::path::{self, Place};
use crate::unit::{moves_to, Arg, Unit};
use crate::Shell;

/// How a unit reads the places it names: whether its wildcards match a
/// leading dot, and whether it goes below the folders it names.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct How {
    pub(super) hidden: bool,
    pub(super) deep: bool,
}

/// How `unit`, a reader known as `key`, reads.
pub(super) fn how(unit: &Unit, key: &str) -> How {
    How {
        hidden: unit.hidden,
        deep: deep(unit, key),
    }
}

impl Context<'_> {
    /// Record a read of `arg`, written from `dir`, that lands at `place`.
    pub(super) fn land(&self, shell: Shell, dir: Option<&Arg>, arg: &Arg, place: Place, how: How) {
        if self.beyond.get() {
            return;
        }
        let from = path::within(dir, arg, shell);
        let beyond = match place {
            Place::Inside
            | Place::Temp { exact: false }
            | Place::Null
            | Place::Workspace { exact: true } => false,
            Place::Sensitive(_, Sensitivity::Secret) => true,
            // The repository's history is inside the workspace.
            Place::Sensitive(_, Sensitivity::History) => false,
            // A startup file or a protected path is the workspace's own
            // only when it is inside it.
            Place::Sensitive(_, Sensitivity::Startup) | Place::Protected(_) => {
                !self.resolver.inside_workspace(&from, shell)
            }
            _ => true,
        };
        // What a pattern can pick, and what a deep read goes below, may be a
        // secret that the place of the folder does not say.
        let pattern = from.known().is_some_and(glob::has_wildcard);
        let beyond = beyond
            || ((how.deep || pattern)
                && self
                    .resolver
                    .reaches_secret(&from, shell, how.hidden, how.deep))
            // A PowerShell or cmd wildcard is the program's own: with a recursion it
            // is a filter on every folder below the one it starts in.
            || (how.deep
                && pattern
                && shell != Shell::Posix
                && self.resolver.reaches_secret(
                    &Arg::Known(path::pattern_folder(from.text())),
                    shell,
                    how.hidden,
                    true,
                ));
        if beyond {
            self.beyond.set(true);
            return;
        }
        // A part like `.*` picks `..` too, in the shells whose patterns match
        // it: the folder above is read.
        if let Some(above) = from.known().and_then(|text| path::climb(text, shell)) {
            self.land_arg(shell, &Arg::Known(above), How { deep: false, ..how });
        }
    }

    /// Record a read of the text `text`, written from where `unit` runs.
    fn land_text(&self, unit: &Unit, text: &str, how: How) -> Kind {
        let from = path::within(unit.dir.as_ref(), &Arg::Known(text.to_string()), unit.shell);
        self.land_arg(unit.shell, &from, how)
    }

    /// Record a read of `from`, a path already joined to where the line
    /// runs: the place it lands, and `Unknown` when that cannot be said.
    fn land_arg(&self, shell: Shell, from: &Arg, how: How) -> Kind {
        let place = self.resolver.place(from, shell, how.hidden);
        self.land(shell, None, from, place, how);
        if matches!(place, Place::Unknown) {
            Kind::Unknown
        } else {
            Kind::Reads
        }
    }
}

/// What `unit`, a reader of its operands, also reads: the working directory
/// when nothing tells it where to look, the repository for `git`, and what
/// its arguments name that the table does not call a place. `Unknown` when
/// the working directory itself is not known (after a `cd` the guard cannot
/// follow).
pub(super) fn reads(
    unit: &Unit,
    key: &str,
    opened: &Opened<'_>,
    how: How,
    context: &Context<'_>,
) -> Kind {
    // A `cd` reads its target, which `judge_unit` placed.
    if moves_to(unit).is_some() {
        return Kind::Reads;
    }
    let mut kind = Kind::Reads;
    if key == "git" {
        // `git -C a -C b` reads the repository at `a/b`: each folder is
        // relative to the one before it, and an absolute one starts over.
        let mut here = path::within(unit.dir.as_ref(), &Arg::Known(".".to_string()), unit.shell);
        for next in &opened.dirs {
            here = path::within(Some(&here), next, unit.shell);
        }
        kind = context.land_arg(unit.shell, &here, how);
        git_paths(unit, opened, how, context);
    } else if implicit(unit, key, opened) {
        let dot = Arg::Known(".".to_string());
        let here = path::within(unit.dir.as_ref(), &dot, unit.shell);
        kind = context.land_arg(unit.shell, &here, how);
    }
    // `df` with no operand reports every disk that is mounted.
    if unit.shell == Shell::Posix && key == "df" && opened.operands == 0 {
        context.beyond.set(true);
    }
    let shallow = How { deep: false, ..how };
    // `echo ~/.ssh/*` opens nothing, but the shell lists the folder.
    if unit.shell == Shell::Posix && takes_no_paths(unit.shell, key) {
        for text in unit.args.iter().filter_map(Arg::known) {
            if glob::has_wildcard(text) {
                context.land_text(unit, text, shallow);
            }
        }
    }
    // `find -newer FILE` reads the file's time.
    if unit.shell == Shell::Posix && key == "find" {
        let mut args = unit.args.iter().filter_map(Arg::known);
        while let Some(text) = args.next() {
            if text.starts_with("-newer") || matches!(text, "-anewer" | "-cnewer" | "-samefile") {
                if let Some(file) = args.next() {
                    context.land_text(unit, file, shallow);
                }
            }
        }
    }
    kind
}

/// What `git` reads in its revisions and pathspecs: paths in the work tree.
/// Some are relative to the repository's root, not to the working directory
/// (`:/x`, `:(top)x`, `:x`, `REV:x`), and the guard does not know where the
/// root is: they are judged from the working directory and from each
/// workspace folder, and a read beyond either wins.
fn git_paths(unit: &Unit, opened: &Opened<'_>, how: How, context: &Context<'_>) {
    let shallow = How { deep: false, ..how };
    let operands = opened.pathspecs.iter().copied();
    let places = opened.places.iter().map(AsRef::<Arg>::as_ref);
    for spec in operands.chain(places) {
        let Some(text) = spec.known() else {
            continue;
        };
        for (rest, from_root) in git_forms(text) {
            context.land_text(unit, rest, shallow);
            if from_root {
                for folder in context.resolver.workspaces() {
                    let at = Arg::Known(format!("{folder}/{rest}"));
                    context.land_arg(unit.shell, &at, shallow);
                }
            }
        }
    }
}

/// The paths a `git` operand names, and whether each is relative to the
/// repository's root: `:/x`, `:(top)x` and every magic pathspec, `:x` and
/// `:0:x` (the index), and `REV:x` (unless `x` starts with `./` or `../`).
fn git_forms(text: &str) -> Vec<(&str, bool)> {
    let relative = |rest: &str| {
        ["./", "../", ".\\", "..\\"]
            .iter()
            .any(|prefix| rest.starts_with(prefix))
    };
    if let Some(body) = text.strip_prefix(':') {
        // A pathspec with magic, or from the root (`:/x`), is the root's
        // whatever follows. `:x` and `:0:x` name a path in the index, from the
        // root unless it starts `./`.
        let (rest, from_root) = if let Some(magic) = body.strip_prefix('(') {
            (magic.split_once(')').map_or(body, |(_, rest)| rest), true)
        } else if let Some(rest) = body.strip_prefix(['/', '!', '^']) {
            (rest, true)
        } else {
            let rest = match body.split_once(':') {
                Some((stage, rest))
                    if !stage.is_empty() && stage.bytes().all(|b| b.is_ascii_digit()) =>
                {
                    rest
                }
                _ => body,
            };
            (rest, !relative(rest))
        };
        return vec![(rest, from_root)];
    }
    match text.split_once(':') {
        // `C:\x` is a path.
        Some((drive, rest))
            if drive.len() == 1
                && drive.bytes().all(|b| b.is_ascii_alphabetic())
                && rest.starts_with(['/', '\\']) =>
        {
            vec![(text, false)]
        }
        Some((_, rest)) => vec![(rest, !relative(rest))],
        None => vec![(text, false)],
    }
}

/// Whether the reader reads the working directory without being told to:
/// every reader that is not known to read only its operands or its input
/// does, when it is given no operand to read.
fn implicit(unit: &Unit, key: &str, opened: &Opened<'_>) -> bool {
    if takes_no_paths(unit.shell, key) {
        return false;
    }
    let bare = opened.operands == 0;
    match unit.shell {
        Shell::Posix => match key {
            "cat" | "head" | "tail" | "wc" | "stat" | "realpath" | "diff" | "sort" | "file"
            | "less" | "df" => false,
            "grep" | "egrep" | "fgrep" => bare && grep_recursive(&unit.args),
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

/// Whether any argument asks for what `letters` (short flags, in a bundle)
/// or `longs` (a long option, by any prefix of its name, as GNU programs
/// read it) mean, or could, being known only when it runs.
fn asks(args: &[Arg], letters: &str, longs: &[&str]) -> bool {
    args.iter().any(|arg| {
        let Some((head, tail)) = shape(arg) else {
            return true;
        };
        if let Some(long) = head.strip_prefix("--") {
            let name = long
                .split('=')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            return (tail && long.is_empty())
                || (!name.is_empty() && longs.iter().any(|full| full.starts_with(&name)))
                || (tail && !long.contains('='));
        }
        match head.strip_prefix('-') {
            Some(bundle) => tail || bundle.chars().any(|letter| letters.contains(letter)),
            None => head.is_empty() && tail,
        }
    })
}

/// Whether a `grep` is given a flag that makes it search folders (`-r`,
/// `-R`, `-d`, `--recursive`, `--directories`, by any prefix of the name).
fn grep_recursive(args: &[Arg]) -> bool {
    asks(
        args,
        "rRd",
        &["recursive", "dereference-recursive", "directories"],
    )
}

/// Whether a PowerShell parameter list asks for `-Recurse` or `-Depth`, by
/// any prefix of the name (`-r`, `-Rec`), as PowerShell reads it.
fn powershell_recursive(args: &[Arg]) -> bool {
    args.iter().any(|arg| match arg.known() {
        None => true,
        Some(text) => text.strip_prefix('-').is_some_and(|name| {
            let name = name
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            !name.is_empty() && ("recurse".starts_with(&name) || "depth".starts_with(&name))
        }),
    })
}

/// Whether a cmd switch list asks for `/s`, every folder below.
fn cmd_recursive(args: &[Arg]) -> bool {
    args.iter().any(|arg| match arg.known() {
        None => true,
        Some(text) => text.strip_prefix(['/', '-']).is_some_and(|body| {
            body.split(':')
                .next()
                .is_some_and(|names| names.to_ascii_lowercase().contains('s'))
        }),
    })
}

/// Whether the reader goes below the folders it names. Shallow only when the
/// table says so for the flags it is given: `cat` and the readers of files,
/// `ls` and `diff` and a PowerShell listing without recursion, `grep` with no
/// recursive flag. Everything else, a reader added later included, is deep.
fn deep(unit: &Unit, key: &str) -> bool {
    if takes_no_paths(unit.shell, key) {
        return false;
    }
    let args = unit.args.as_slice();
    match unit.shell {
        Shell::Posix => match key {
            "cat" | "head" | "tail" | "wc" | "stat" | "realpath" | "sort" | "file" | "less"
            | "df" => false,
            "ls" => asks(args, "R", &["recursive"]),
            "diff" => asks(args, "rR", &["recursive"]),
            "grep" | "egrep" | "fgrep" => grep_recursive(args),
            _ => true,
        },
        Shell::PowerShell => match key {
            "get-content" | "cat" | "gc" | "type" | "select-string" | "sls" | "get-item"
            | "test-path" | "resolve-path" => false,
            "get-childitem" => powershell_recursive(args),
            _ => true,
        },
        Shell::Cmd => match key {
            "type" => false,
            "dir" | "findstr" => cmd_recursive(args),
            _ => true,
        },
    }
}
