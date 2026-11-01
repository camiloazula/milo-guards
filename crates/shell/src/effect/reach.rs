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

use milo_guards_core::spelling::{glob, verbatim};
use milo_guards_core::Sensitivity;

use super::operands::{shape, takes_no_paths, Context, Opened};
use super::paths::Landed;
use super::Kind;
use crate::path::{self, Place};
use crate::unit::{moves_to, Arg, Unit};
use crate::Shell;

/// How a unit reads the places it names: whether its wildcards match a
/// leading dot, whether it goes below the folders it names, and how it walks
/// them.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Manner {
    pub(super) hidden: bool,
    pub(super) deep: bool,
    pub(super) walk: Walk,
}

impl Manner {
    /// The same unit, reading only what a place names and nothing below it.
    pub(super) fn shallow(self) -> Self {
        Self {
            deep: false,
            walk: Walk::No,
            ..self
        }
    }
}

/// How a unit walks the folders it names, for the paths a line reads.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum Walk {
    /// It does not walk them: it opens only what it names, or goes into a
    /// folder (`cd`) and reads nothing below it.
    #[default]
    No,
    /// It walks them and does not open what it finds through symbolic links.
    Stays,
    /// It walks them and opens what it finds through symbolic links.
    Follows,
}

/// How `unit`, a reader known as `key`, reads.
pub(super) fn how(unit: &Unit, key: &str, paths: bool) -> Manner {
    let deep = deep(unit, key);
    let walk = match () {
        () if !deep || moves_to(unit).is_some() => Walk::No,
        // How a walk treats links is only asked for by the paths.
        () if !paths => Walk::No,
        () if follows_links(unit, key) => Walk::Follows,
        () => Walk::Stays,
    };
    Manner {
        hidden: unit.hidden,
        deep,
        walk,
    }
}

impl Context<'_> {
    /// Record a read of `arg`, written from `dir`, that lands at `place`.
    pub(super) fn land(
        &self,
        shell: Shell,
        dir: Option<&Arg>,
        arg: &Arg,
        place: Place,
        how: Manner,
    ) {
        let from = path::within(dir, arg, shell);
        // The text is the operand's own, or the folder it was joined to in
        // front of a relative one.
        let joined = from != *arg;
        self.record(shell, &from, joined, place, how);
    }

    /// Record a read of `from`, a path already joined to where the line runs,
    /// that lands at `place`. `joined` says whether `from` is the folder a
    /// `cd` moved to with a relative operand after it, and not a path the line
    /// wrote out whole.
    fn record(&self, shell: Shell, from: &Arg, joined: bool, place: Place, how: Manner) {
        // Once a read is beyond the workspace the answer is settled, unless
        // the paths are asked for: those are every read, so each is kept.
        if self.beyond.get() && self.landed.is_none() {
            return;
        }
        if let (Some(landed), Some(text)) = (&self.landed, from.known()) {
            let (text, glob) = folder_read(text, shell);
            for folded in self.foldings(&text, joined, shell) {
                landed.borrow_mut().push(Landed {
                    text: text.clone(),
                    folded,
                    glob: glob.clone(),
                    walk: how.walk,
                    shell,
                    stage: self.stage.get(),
                });
            }
        }
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
                !self.resolver.inside_workspace(from, shell)
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
                    .reaches_secret(from, shell, how.hidden, how.deep))
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
            if self.landed.is_none() {
                return;
            }
        }
        // A part like `.*` picks `..` too, in the shells whose patterns match
        // it: the folder above is read.
        if let Some(above) = from.known().and_then(|text| path::climb(text, shell)) {
            self.land_arg(shell, &Arg::Known(above), joined, how.shallow());
        }
    }

    /// How many leading bytes of `text`, a path as joined to where the line
    /// runs, the shell has already applied the `..` of, once for each way the
    /// shell can have gone: a `cd` applies its own by spelling (`cd src/..` is
    /// the folder `src` is in), so the folder the line moved to, and a `cd`
    /// target as a whole, are folded. Only a relative operand joined to that
    /// folder starts with it: a path the line wrote out whole (absolute, or
    /// `~`) is opened by a program from its first part, whatever it spells
    /// like the folder. The rest is opened by a program, which gets a `..`
    /// after the link before it.
    ///
    /// A line that keeps the physical path (`cd -P`, `set -P`) may keep it for
    /// one `cd` and not another: the flag is the line's, and the last of `-L`
    /// and `-P` decides each `cd`, so which `cd` is physical is not told here.
    /// Such a line has the kept way (a `0`) as well as the folded one, and a
    /// caller checks both. And bash and zsh fall back to the path as written
    /// when the folded folder does not exist, and check the folder before
    /// every `..` that follows a part: with `link -> /etc` and no `etc` beside
    /// it, `cd link/../etc/..` goes to `/`, not to the folded `<cwd>`. So a
    /// part after a `..` that climbed out of a part, anywhere in the folder,
    /// gives a second way, the text with every `..` kept (a `0`), and both are
    /// returned for a caller to check. A folder with no part after such a `..`
    /// (`cd link/..`, `cd src/../..`) has one way.
    fn foldings(&self, text: &str, joined: bool, shell: Shell) -> Vec<usize> {
        let (folded, second_way) = if self.cd_target.get() {
            (text.len(), dots_before_a_part(text, shell))
        } else {
            let dir = self.dir.borrow();
            match dir.as_deref().filter(|dir| {
                joined
                    && text
                        .strip_prefix(dir)
                        .is_some_and(|rest| rest.starts_with('/'))
            }) {
                Some(dir) => (dir.len(), dots_before_a_part(dir, shell)),
                None => (0, false),
            }
        };
        if (second_way || self.physical) && folded != 0 {
            vec![folded, 0]
        } else {
            vec![folded]
        }
    }

    /// Record a read of the text `text`, written from where `unit` runs.
    fn land_text(&self, unit: &Unit, text: &str, how: Manner) -> Kind {
        let from = path::within(unit.dir.as_ref(), &Arg::Known(text.to_string()), unit.shell);
        let joined = from.known() != Some(text);
        self.land_arg(unit.shell, &from, joined, how)
    }

    /// Record a read of `from`, a path already joined to where the line
    /// runs (`joined` as in [`record`](Self::record)): the place it lands, and
    /// `Unknown` when that cannot be said.
    fn land_arg(&self, shell: Shell, from: &Arg, joined: bool, how: Manner) -> Kind {
        let place = self.resolver.place_joined(from, shell, how.hidden);
        self.record(shell, from, joined, place, how);
        if matches!(place, Place::Unknown) {
            Kind::Unknown
        } else {
            Kind::Reads
        }
    }
}

/// Whether a POSIX `text` has a part that came after a `..` which climbed out
/// of a part, anywhere in it, whether or not the part is still there at the
/// end (`link/../etc`, `link/../etc/..`, `a/../b/..`, `/a/b/../c`; not
/// `link/..`, `src/../..`, `../x`). The shell applies a `..` by spelling, but
/// bash and zsh check the folder before every `..` that follows a part, and go
/// to the path as written when that check fails (`cd a/../nonexist/..` fails
/// in them although the folded folder exists). Only a part after such a `..`
/// can fail to exist: the folder before it is a leading part of the text, which
/// exists when the text does, and a `..` with no part before it climbs from
/// the folder the line is in, which is known.
fn dots_before_a_part(text: &str, shell: Shell) -> bool {
    if shell != Shell::Posix {
        return false;
    }
    // The parts that remain, and whether a part has come after a `..` that
    // climbed out of one.
    let mut kept = 0usize;
    let mut dotted = false;
    for name in text.split('/') {
        match name {
            "" | "." => {}
            ".." => {
                if kept > 0 {
                    kept -= 1;
                    dotted = true;
                }
            }
            _ => {
                if dotted {
                    return true;
                }
                kept += 1;
            }
        }
    }
    false
}

/// The place a read of `text` opens on disk, and for a pattern what follows
/// it: the path itself, or the fixed folder the pattern expands in (`src` for
/// `src/*.rs`, `.` when no folder is written) and the rest of the pattern
/// below it (`*.rs`), since the names it picks are the disk's.
fn folder_read(text: &str, shell: Shell) -> (String, Option<String>) {
    // What comes before the path proper is not part of the pattern: a long
    // path's `\\?\` holds a `?`, and PowerShell's `FileSystem::` a colon.
    let mut skip = 0;
    while let Some(len) = verbatim(&text[skip..])
        .map(|rest| text.len() - skip - rest.len())
        .or_else(|| {
            let (provider, _) = text[skip..]
                .split_once("::")
                .filter(|_| shell == Shell::PowerShell)?;
            Some(provider.len() + 2)
        })
    {
        skip += len;
    }
    let (prefix, body) = text.split_at(skip);
    if !glob::has_wildcard(body) {
        return (text.to_string(), None);
    }
    let folder = path::pattern_folder(body);
    let drive = shell != Shell::Posix
        && body.len() > 2
        && body.as_bytes()[0].is_ascii_alphabetic()
        && body.as_bytes()[1] == b':';
    let folder = match body[if drive { 2 } else { 0 }..].chars().next() {
        // `C:\*` expands in `C:\`, not in the drive's own working directory.
        Some(separator @ ('/' | '\\')) if drive && folder.len() == 2 => {
            format!("{folder}{separator}")
        }
        // `C:*` is the working directory of the drive.
        _ if drive && folder == "." => body[..2].to_string(),
        _ => folder,
    };
    // The rest is what is written after the folder, as written. When no
    // folder is written the folder is `.`, which is not in the text: a
    // leading dot is part of the pattern (`.a*/x`, `.*`).
    let separators = flavour_separators(shell);
    let rest = match body.strip_prefix(folder.as_str()) {
        Some(rest)
            if rest.is_empty()
                || rest.starts_with(separators)
                || folder.ends_with(separators)
                || folder.ends_with(':') =>
        {
            rest
        }
        _ => body,
    };
    let rest = rest.trim_start_matches(separators);
    (format!("{prefix}{folder}"), Some(rest.to_string()))
}

/// The characters that separate the parts of a path for `shell`.
fn flavour_separators(shell: Shell) -> &'static [char] {
    if shell == Shell::Posix {
        &['/']
    } else {
        &['/', '\\']
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
    how: Manner,
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
        // Still the folder a `cd` moved to, until an absolute one starts over.
        let mut joined = unit.dir.is_some();
        for next in &opened.dirs {
            let after = path::within(Some(&here), next, unit.shell);
            joined &= after != **next;
            here = after;
        }
        kind = context.land_arg(unit.shell, &here, joined, how);
        git_paths(unit, opened, how, context);
    } else if implicit(unit, key, opened) {
        let dot = Arg::Known(".".to_string());
        let here = path::within(unit.dir.as_ref(), &dot, unit.shell);
        kind = context.land_arg(unit.shell, &here, unit.dir.is_some(), how);
    }
    // `df` with no operand reports every disk that is mounted.
    if unit.shell == Shell::Posix && key == "df" && opened.operands == 0 {
        context.beyond.set(true);
    }
    let shallow = how.shallow();
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
fn git_paths(unit: &Unit, opened: &Opened<'_>, how: Manner, context: &Context<'_>) {
    let shallow = how.shallow();
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
                    context.land_arg(unit.shell, &at, false, shallow);
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

/// The flags of one walker that are known not to make it open what it finds
/// through symbolic links, for [`follows_links`]. Everything else is not on
/// the list.
struct Flags {
    /// Short flags that take no value, in a bundle (`-rn`).
    short: &'static str,
    /// Short flags that take a value, attached or in the next word: the rest
    /// of the bundle is that value.
    valued: &'static str,
    /// Long flags that take no value, spelled out (an abbreviation is not on
    /// the list: programs read it, so it could be any flag).
    long: &'static [&'static str],
    /// Long flags that take a value (`--glob=x` or `--glob x`).
    long_valued: &'static [&'static str],
    /// Words with a single dash, for the programs that spell their flags so
    /// (`find -name`). Empty for the rest, whose single dash is a bundle.
    words: &'static [&'static str],
}

const LS: Flags = Flags {
    short: "aAlhFpdRrtSucUfgGinosCxmqbBk1",
    valued: "ITw",
    long: &[
        "all",
        "almost-all",
        "human-readable",
        "recursive",
        "reverse",
        "classify",
        "directory",
        "inode",
        "numeric-uid-gid",
        "size",
        "group-directories-first",
        "literal",
        "hide-control-chars",
        "si",
        "no-group",
        "author",
        "escape",
    ],
    long_valued: &[
        "color",
        "sort",
        "time",
        "format",
        "time-style",
        "hide",
        "ignore",
        "block-size",
        "width",
        "tabsize",
        "indicator-style",
        "quoting-style",
    ],
    words: &[],
};

const DU: Flags = Flags {
    short: "ahkmscxbSP0",
    valued: "dBt",
    long: &[
        "all",
        "human-readable",
        "summarize",
        "total",
        "one-file-system",
        "apparent-size",
        "bytes",
        "separate-dirs",
        "count-links",
        "si",
        "no-dereference",
        "null",
        "inodes",
    ],
    long_valued: &[
        "max-depth",
        "block-size",
        "threshold",
        "exclude",
        "time",
        "time-style",
    ],
    words: &[],
};

const GREP: Flags = Flags {
    short: "abcEFGhHiIlLnoOpPqrsTUvVwxyzZ",
    valued: "efmABCDd",
    long: &[
        "recursive",
        "ignore-case",
        "no-ignore-case",
        "line-number",
        "count",
        "files-with-matches",
        "files-without-match",
        "no-messages",
        "quiet",
        "silent",
        "invert-match",
        "word-regexp",
        "line-regexp",
        "only-matching",
        "no-filename",
        "with-filename",
        "extended-regexp",
        "fixed-strings",
        "perl-regexp",
        "basic-regexp",
        "text",
        "null",
        "null-data",
        "initial-tab",
        "no-group-separator",
        "byte-offset",
        "unix-byte-offsets",
    ],
    long_valued: &[
        "regexp",
        "file",
        "max-count",
        "after-context",
        "before-context",
        "context",
        "include",
        "exclude",
        "exclude-dir",
        "exclude-from",
        "color",
        "colour",
        "binary-files",
        "devices",
        "directories",
        "label",
        "group-separator",
    ],
    words: &[],
};

const RG: Flags = Flags {
    short: "nNiIsSuUvwxlcqoHhzaFP.",
    valued: "ABCefgjmMrtTE",
    long: &[
        "ignore-case",
        "case-sensitive",
        "smart-case",
        "line-number",
        "no-line-number",
        "with-filename",
        "no-filename",
        "files-with-matches",
        "files-without-match",
        "count",
        "count-matches",
        "only-matching",
        "quiet",
        "invert-match",
        "word-regexp",
        "line-regexp",
        "fixed-strings",
        "hidden",
        "no-heading",
        "heading",
        "no-ignore",
        "no-ignore-vcs",
        "unrestricted",
        "multiline",
        "text",
        "binary",
        "pcre2",
        "json",
        "stats",
        "files",
        "vimgrep",
        "column",
        "null",
        "trim",
        "no-messages",
        "no-config",
        "pretty",
    ],
    long_valued: &[
        "regexp",
        "file",
        "glob",
        "iglob",
        "type",
        "type-not",
        "max-count",
        "after-context",
        "before-context",
        "context",
        "max-depth",
        "threads",
        "replace",
        "color",
        "colors",
        "sort",
        "sortr",
        "max-columns",
        "encoding",
        "max-filesize",
    ],
    words: &[],
};

const FD: Flags = Flags {
    short: "HIsiaFpg0",
    valued: "etEdSj",
    long: &[
        "hidden",
        "no-ignore",
        "no-ignore-vcs",
        "case-sensitive",
        "ignore-case",
        "glob",
        "fixed-strings",
        "absolute-path",
        "full-path",
        "print0",
    ],
    long_valued: &[
        "extension",
        "type",
        "exclude",
        "max-depth",
        "min-depth",
        "size",
        "color",
        "threads",
        "changed-within",
        "changed-before",
    ],
    words: &[],
};

const FIND: Flags = Flags {
    short: "",
    valued: "",
    long: &[],
    long_valued: &[],
    words: &[
        "-H",
        "-P",
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-wholename",
        "-iwholename",
        "-regex",
        "-iregex",
        "-regextype",
        "-type",
        "-size",
        "-mtime",
        "-atime",
        "-ctime",
        "-mmin",
        "-amin",
        "-cmin",
        "-newer",
        "-empty",
        "-perm",
        "-user",
        "-group",
        "-uid",
        "-gid",
        "-nouser",
        "-nogroup",
        "-maxdepth",
        "-mindepth",
        "-depth",
        "-prune",
        "-print",
        "-print0",
        "-printf",
        "-quit",
        "-o",
        "-a",
        "-and",
        "-or",
        "-not",
        "-readable",
        "-writable",
        "-executable",
        "-links",
        "-inum",
        "-true",
        "-false",
        "-mount",
        "-xdev",
        "-noleaf",
        "-ls",
    ],
};

/// Whether every flag in `args` is one `flags` lists. What is not a flag (an
/// operand, a pattern, a value) is not judged; a flag that is only partly
/// known is not on the list.
fn only_listed(args: &[Arg], flags: &Flags) -> bool {
    for arg in args {
        let Some((head, tail)) = shape(arg) else {
            return false;
        };
        if head == "--" && !tail {
            return true;
        }
        // A number is the value of a test (`find -mtime -3`), not a flag.
        let number = !flags.words.is_empty()
            && head.len() > 1
            && head.starts_with('-')
            && head[1..].chars().all(|c| c.is_ascii_digit());
        if !head.starts_with('-') || head == "-" || number {
            continue;
        }
        if tail {
            return false;
        }
        let listed = if let Some(long) = head.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or_default();
            flags.long.contains(&name) || flags.long_valued.contains(&name)
        } else if !flags.words.is_empty() {
            flags.words.contains(&head)
        } else {
            let mut bundle = head[1..].chars();
            loop {
                match bundle.next() {
                    None => break true,
                    Some(letter) if flags.valued.contains(letter) => break true,
                    Some(letter) if flags.short.contains(letter) => {}
                    Some(_) => break false,
                }
            }
        };
        if !listed {
            return false;
        }
    }
    true
}

/// Whether the reader, when it goes below the folders it names, opens what it
/// finds through symbolic links. It does not only when it is on this list of
/// walkers that stay out of them and every flag it is given is one that
/// walker's own list says does not change that: `ls -R` and `du` (not `-L`,
/// `-H`, `--dereference`), `grep -r` (not `-R`, `-S`), `rg` and `fd` (not
/// `-L`, `--follow`), `find` (not `-L`, `-follow`, `-xtype`, and no `-exec` or
/// `-ok`, which open the names it finds), and `git`, which reads the index and
/// the objects and takes a link as a link (not `--no-index`). Any other flag,
/// an abbreviation of one included, or any other reader, a reader added later
/// and everything in PowerShell and cmd included, is taken to follow them.
/// `find -H` and `grep -O` follow only the folder named on the command line,
/// which is the root, and stay on the list.
fn follows_links(unit: &Unit, key: &str) -> bool {
    if unit.shell != Shell::Posix {
        return true;
    }
    let args = unit.args.as_slice();
    let flags = match key {
        "ls" => &LS,
        "du" => &DU,
        "grep" | "egrep" | "fgrep" => &GREP,
        "rg" => &RG,
        "fd" => &FD,
        "find" => &FIND,
        "git" => {
            return args
                .iter()
                .any(|arg| arg.known().is_none_or(|text| text == "--no-index"));
        }
        _ => return true,
    };
    !only_listed(args, flags)
}
