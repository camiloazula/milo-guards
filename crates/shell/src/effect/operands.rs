//! Which arguments of a reader are places it opens, and whether each is one
//! the guard can name, for [`super::of`].
//!
//! A reader of a place known only when it runs may read a network device or a
//! share, so it is not reads-only. But only what the program opens as a file
//! is a place: a pattern, a count or an author (`grep "$P" .`, `head -n "$N"
//! x`) is not, and each reader's table entry says which arguments are
//! places.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};

use super::paths::Landed;
use super::reach::{self, Manner};
use super::{git, git_subcommand, Kind};
use crate::path::{Access, Place, Resolver};
use crate::powershell::Params;
use crate::unit::{Arg, Binding, Stage, Unit};
use crate::Shell;

/// What judging a unit needs besides the unit.
pub(super) struct Context<'a> {
    pub(super) resolver: &'a Resolver,
    /// The first unit at each pipeline stage, for what a stage is handed.
    pub(super) producers: HashMap<(usize, usize), &'a Unit>,
    /// Whether a read of the line landed beyond the workspace so far, for
    /// [`super::Reach`].
    pub(super) beyond: Cell<bool>,
    /// Where each read landed, as written, when the caller asks for the
    /// paths (`None` otherwise, so that `effect` pays nothing for them).
    pub(super) landed: Option<RefCell<Vec<Landed>>>,
    /// The pipeline stages whose listing a later stage hands to a program that
    /// opens the names, as (pipeline, index).
    pub(super) followed: RefCell<BTreeSet<(usize, usize)>>,
    /// The stage of the unit being read.
    pub(super) stage: Cell<Option<Stage>>,
    /// Whether the line keeps the physical path as its working directory
    /// (`cd -P`) somewhere: a `cd` of it may follow links before it applies a
    /// `..`, so a read is listed both ways, as the flag is the line's and not
    /// each `cd`'s.
    pub(super) physical: bool,
    /// The folder the unit being read runs in, where a `cd` moved the line,
    /// as written.
    pub(super) dir: RefCell<Option<String>>,
    /// Whether the unit being read is a `cd`, whose target the shell applies
    /// the `..` of itself (bash and zsh fall back to the physical path when
    /// the folded folder does not exist, so a target is also listed kept).
    pub(super) cd_target: Cell<bool>,
}

/// Whether reading from `arg`, written from `dir`, is a read of a place the
/// guard can name and that is on this machine. Not when it is known only
/// when it runs, nor bash's `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT`, nor
/// on Windows a UNC path (`\\server\share`, `//server/share`,
/// `\\?\UNC\server\share`): reading those contacts the network, and a share
/// is offered the user's credentials.
pub(super) fn place_effect(
    context: &Context<'_>,
    shell: Shell,
    dir: Option<&Arg>,
    arg: &Arg,
    how: Manner,
) -> Kind {
    let (kind, place) = place_kind(context.resolver, shell, dir, arg, how.hidden);
    if let Some(place) = place {
        context.land(shell, dir, arg, place, how);
    }
    kind
}

/// As [`place_effect`], without saying where the read lands: the answer, and
/// the place when the argument was read that far.
pub(super) fn place_kind(
    resolver: &Resolver,
    shell: Shell,
    dir: Option<&Arg>,
    arg: &Arg,
    hidden: bool,
) -> (Kind, Option<Place>) {
    // PowerShell's `$null` is the null device, which holds nothing.
    if matches!(arg, Arg::Null) {
        return (Kind::Reads, Some(Place::Null));
    }
    let Some(text) = arg.known() else {
        return (Kind::Unknown, None);
    };
    // PowerShell expands a variable inside a bare token (`--contents=$p`),
    // which its parse reads as written (`2>$null` is the null device).
    if (shell == Shell::PowerShell
        && text.contains('$')
        && !text.to_ascii_lowercase().ends_with("$null"))
        || (shell == Shell::Posix && names_network_device(text))
        || resolver.network(dir, arg, shell)
    {
        return (Kind::Unknown, None);
    }
    let place = resolver.place(dir, arg, shell, hidden, Access::Item);
    if matches!(place, Place::Unknown) {
        (Kind::Unknown, Some(place))
    } else {
        (Kind::Reads, Some(place))
    }
}

/// Whether `text` names one of bash's network devices.
pub(super) fn names_network_device(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("/dev/tcp/") || lower.contains("/dev/udp/")
}

/// A reader reads the places its path arguments name, so each must be one
/// the guard can name: a glob is a pattern over known folders and stays
/// known, a path known only when it runs (`cat $f`) does not. A name of the
/// network anywhere in the arguments is not reading. What a pipeline hands the
/// unit counts when the stages before it list known places.
pub(super) fn operands(unit: &Unit, key: &str, context: &Context<'_>) -> Kind {
    let mut effect = Kind::Reads;
    // A value inside an argument (`--exclude-from=\\evil\s\x`, `-O//evil/s/x`,
    // `/f:\\evil\x`) is checked for the spelling of a network device or a
    // share, like a whole argument, whatever option it belongs to.
    for text in unit.args.iter().filter_map(Arg::known) {
        let network = values(text).any(|value| {
            (unit.shell == Shell::Posix && names_network_device(value))
                || context.resolver.network(
                    unit.dir.as_ref(),
                    &Arg::Known(value.to_string()),
                    unit.shell,
                )
        });
        if network {
            effect = Kind::Unknown;
        }
    }
    let opened = path_args(unit, key);
    let how = reach::how(unit, key, context.landed.is_some());
    // A folder `-C` names is judged like a place; where it lands is the
    // repository's, which the folders chained together make.
    for dir in &opened.dirs {
        if place_kind(
            context.resolver,
            unit.shell,
            unit.dir.as_ref(),
            dir,
            unit.hidden,
        )
        .0 == Kind::Unknown
        {
            effect = Kind::Unknown;
        }
    }
    for arg in &opened.places {
        let own = match arg.as_ref() {
            // What a listing hands on is read where it was listed, which is
            // judged there.
            Arg::Input if fed_by_listing(unit, context, false) => Kind::Reads,
            Arg::Input => Kind::Unknown,
            known => place_effect(context, unit.shell, unit.dir.as_ref(), known, how),
        };
        if own == Kind::Unknown {
            effect = Kind::Unknown;
        }
    }
    // A cmdlet that takes a path from the pipeline by value or by property
    // name reads whatever an earlier stage hands it, which is a path only
    // when that stage lists known places.
    if unit.shell == Shell::PowerShell && binds_pipeline(key) {
        let text = matches!(key, "select-string" | "sls");
        let handed = unit.stage.is_some_and(|stage| stage.index > 0);
        if handed && !fed_by_listing(unit, context, text) {
            effect = Kind::Unknown;
        }
    }
    // Where it reads without being told, and what its operands reach that
    // the table does not call a place.
    if reach::reads(unit, key, &opened, how, context) == Kind::Unknown {
        effect = Kind::Unknown;
    }
    effect
}

/// An argument, and the values inside it: what follows the first `=` or `:`,
/// and what is attached to a short option (`-Ovalue`).
fn values(text: &str) -> impl Iterator<Item = &str> {
    let attached = text
        .strip_prefix('-')
        .filter(|rest| !rest.starts_with('-'))
        .and_then(|rest| rest.get(1..))
        .filter(|rest| !rest.is_empty());
    [
        Some(text),
        text.split_once('=').map(|(_, value)| value),
        text.split_once(':').map(|(_, value)| value),
        attached,
    ]
    .into_iter()
    .flatten()
}

/// The PowerShell cmdlets whose path parameters take pipeline input.
pub(crate) fn binds_pipeline(key: &str) -> bool {
    matches!(
        key,
        "get-childitem"
            | "get-item"
            | "test-path"
            | "resolve-path"
            | "get-content"
            | "cat"
            | "gc"
            | "type"
            | "select-string"
            | "sls"
    )
}

/// Programs that print or test their arguments and open none of them.
pub(super) fn takes_no_paths(shell: Shell, key: &str) -> bool {
    match shell {
        Shell::Posix => matches!(
            key,
            "echo"
                | "printf"
                | "true"
                | "false"
                | "test"
                | "["
                | "basename"
                | "dirname"
                | "which"
                | "pwd"
                | "pushd"
        ),
        Shell::PowerShell => matches!(
            key,
            "write-output"
                | "write-host"
                | "echo"
                | "where-object"
                | "select-object"
                | "sort-object"
                | "measure-object"
                | "get-location"
                | "pwd"
        ),
        Shell::Cmd => matches!(key, "echo" | "cd" | "chdir"),
    }
}

// What a pipeline hands on.

/// Whether the unit's output is the names of what is in known places: `ls`,
/// `fd`, `dir`, `Get-ChildItem`, `git ls-files`, and a `find` that prints only
/// what it finds (`-printf` and `-exec` print any text).
pub(crate) fn lists(unit: &Unit) -> bool {
    let Some(key) = unit.key() else {
        return false;
    };
    match key.as_str() {
        "ls" | "fd" | "dir" | "get-childitem" => true,
        "find" => !unit.args.iter().filter_map(Arg::known).any(|text| {
            matches!(
                text,
                "-printf" | "-fprintf" | "-exec" | "-execdir" | "-ok" | "-okdir"
            )
        }),
        "git" => git_subcommand(&unit.args) == Some("ls-files"),
        _ => false,
    }
}

/// Whether the unit only selects, orders or shows part of what it is handed
/// (so what it hands on is still what the stage before it listed): it reads
/// no file of its own.
pub(crate) fn passes(unit: &Unit) -> bool {
    let Some(key) = unit.key() else {
        return false;
    };
    match unit.shell {
        Shell::Posix => {
            matches!(
                key.as_str(),
                "head" | "tail" | "sort" | "grep" | "egrep" | "fgrep"
            ) && path_args(unit, &key).places.is_empty()
        }
        Shell::PowerShell => match key.as_str() {
            "where-object" | "sort-object" => true,
            // `-Property` and a first argument can make up the objects.
            "select-object" => unit.args.iter().all(|arg| {
                arg.known().is_some_and(|text| {
                    let name = text.trim_start_matches('-').to_ascii_lowercase();
                    (text.starts_with('-')
                        && matches!(
                            name.as_str(),
                            "first" | "last" | "skip" | "skiplast" | "unique" | "index" | "wait"
                        ))
                        || text.chars().all(|c| c.is_ascii_digit())
                })
            }),
            _ => false,
        },
        Shell::Cmd => false,
    }
}

/// Whether what the stage before `unit` hands it is names from a listing,
/// through any stage that only passes them on. `text` says strings and
/// search results do as well, for a cmdlet that searches them rather than
/// opens them.
///
/// It also notes the stage that lists, in `context.followed`, for the paths.
fn fed_by_listing(unit: &Unit, context: &Context<'_>, text: bool) -> bool {
    let mut at = unit.stage;
    while let Some(stage) = at.filter(|stage| stage.index > 0) {
        let Some(producer) = context
            .producers
            .get(&(stage.pipeline, stage.index - 1))
            .copied()
        else {
            return false;
        };
        if lists(producer) {
            // The names are opened by the stage that is handed them, so the
            // folder that was listed is read through whatever is in it.
            let lister = (stage.pipeline, stage.index - 1);
            context.followed.borrow_mut().insert(lister);
            return true;
        }
        if text
            && producer.key().is_some_and(|key| {
                matches!(
                    key.as_str(),
                    "get-content" | "cat" | "gc" | "type" | "select-string" | "sls"
                )
            })
        {
            return true;
        }
        if !passes(producer) {
            return false;
        }
        at = producer.stage;
    }
    false
}

// The path arguments of each reader.

/// How a program's arguments divide: which options take a value that is not
/// a place, which take a file, and whether the first operand is a pattern.
#[derive(Default)]
struct Spec {
    /// Short options whose value is not a place.
    valued: &'static str,
    valued_longs: &'static [&'static str],
    /// Short options whose value is a file the program reads.
    files: &'static str,
    file_longs: &'static [&'static str],
    /// Options whose value is a file that lists files to open: the guard
    /// never sees the list, so the line is `Unknown` whatever it names.
    lists: &'static str,
    list_longs: &'static [&'static str],
    /// Whether the first operand is a pattern.
    pattern: bool,
    /// The options that give the pattern or the places instead, so that no
    /// operand is the pattern.
    given: &'static str,
    given_longs: &'static [&'static str],
}

const LS: Spec = Spec {
    valued: "IwT",
    valued_longs: &[
        "hide",
        "ignore",
        "block-size",
        "color",
        "format",
        "indicator-style",
        "quoting-style",
        "sort",
        "time",
        "time-style",
        "tabsize",
        "width",
    ],
    ..none()
};
const HEAD: Spec = Spec {
    valued: "nc",
    valued_longs: &["lines", "bytes"],
    ..none()
};
const TAIL: Spec = Spec {
    valued: "ncs",
    valued_longs: &[
        "lines",
        "bytes",
        "pid",
        "sleep-interval",
        "max-unchanged-stats",
    ],
    ..none()
};
const STAT: Spec = Spec {
    valued: "c",
    valued_longs: &["format", "printf"],
    ..none()
};
const WC: Spec = Spec {
    list_longs: &["files0-from"],
    ..none()
};
const DU: Spec = Spec {
    valued: "dBtI",
    valued_longs: &[
        "max-depth",
        "block-size",
        "threshold",
        "exclude",
        "time",
        "time-style",
    ],
    files: "X",
    file_longs: &["exclude-from"],
    list_longs: &["files0-from"],
    ..none()
};
const DF: Spec = Spec {
    valued: "Btx",
    valued_longs: &["block-size", "type", "exclude-type"],
    ..none()
};
const REALPATH: Spec = Spec {
    file_longs: &["relative-to", "relative-base"],
    ..none()
};
const DIFF: Spec = Spec {
    valued: "UCxILDWF",
    valued_longs: &[
        "unified",
        "context",
        "exclude",
        "ignore-matching-lines",
        "label",
        "ifdef",
        "width",
        "show-function-line",
    ],
    files: "SX",
    file_longs: &["starting-file", "exclude-from", "from-file", "to-file"],
    ..none()
};
const SORT: Spec = Spec {
    valued: "ktST",
    valued_longs: &[
        "key",
        "field-separator",
        "buffer-size",
        "temporary-directory",
        "parallel",
        "batch-size",
    ],
    file_longs: &["random-source"],
    list_longs: &["files0-from"],
    ..none()
};
const FILE: Spec = Spec {
    valued: "eP",
    files: "m",
    file_longs: &["magic-file"],
    lists: "f",
    list_longs: &["files-from"],
    ..none()
};
const LESS: Spec = Spec {
    valued: "bhjpPtxyz#",
    files: "T",
    ..none()
};
const GREP: Spec = Spec {
    valued: "mABCdDe",
    valued_longs: &[
        "max-count",
        "after-context",
        "before-context",
        "context",
        "include",
        "exclude",
        "exclude-dir",
        "label",
        "color",
        "colour",
        "binary-files",
        "directories",
        "devices",
        "regexp",
        "group-separator",
    ],
    files: "f",
    file_longs: &["file", "exclude-from"],
    pattern: true,
    given: "ef",
    given_longs: &["regexp", "file"],
    ..none()
};
const RG: Spec = Spec {
    valued: "gtTmABCjEMrde",
    valued_longs: &[
        "glob",
        "iglob",
        "type",
        "type-not",
        "type-add",
        "type-clear",
        "max-count",
        "after-context",
        "before-context",
        "context",
        "threads",
        "encoding",
        "max-columns",
        "replace",
        "max-depth",
        "maxdepth",
        "sort",
        "sortr",
        "colors",
        "color",
        "context-separator",
        "field-context-separator",
        "field-match-separator",
        "max-filesize",
        "path-separator",
        "engine",
        "dfa-size-limit",
        "regex-size-limit",
        "regexp",
        "hyperlink-format",
        "pre-glob",
    ],
    files: "f",
    file_longs: &["file", "ignore-file"],
    pattern: true,
    given: "ef",
    given_longs: &["regexp", "file", "files", "type-list", "help", "version"],
    ..none()
};
const FD: Spec = Spec {
    valued: "eEtdSjco",
    valued_longs: &[
        "extension",
        "exclude",
        "type",
        "max-depth",
        "min-depth",
        "exact-depth",
        "size",
        "threads",
        "color",
        "owner",
        "changed-within",
        "changed-before",
        "max-results",
        "format",
        "hyperlink",
    ],
    file_longs: &["base-directory", "search-path", "ignore-file"],
    pattern: true,
    ..none()
};

/// A spec with nothing set, for `..none()` in the constants.
const fn none() -> Spec {
    Spec {
        valued: "",
        valued_longs: &[],
        files: "",
        file_longs: &[],
        lists: "",
        list_longs: &[],
        pattern: false,
        given: "",
        given_longs: &[],
    }
}

/// A spec with nothing set.
const NONE: Spec = none();

// Programs that are not reads-only (they may write, or `effect` has not been
// taught them) but show or pass on what is in the files they open, for the
// rule that reports a read of a secret. Each entry says what the program's
// own options take, so a value is not mistaken for a file.

const NL: Spec = Spec {
    valued: "bfhdilnsvw",
    valued_longs: &[
        "body-numbering",
        "footer-numbering",
        "header-numbering",
        "section-delimiter",
        "line-increment",
        "join-blank-lines",
        "number-format",
        "number-separator",
        "starting-line-number",
        "number-width",
    ],
    ..none()
};
const TAC: Spec = Spec {
    valued: "s",
    valued_longs: &["separator"],
    ..none()
};
const FOLD: Spec = Spec {
    valued: "w",
    valued_longs: &["width"],
    ..none()
};
const PASTE: Spec = Spec {
    valued: "d",
    valued_longs: &["delimiters"],
    ..none()
};
const CUT: Spec = Spec {
    valued: "bcdf",
    valued_longs: &[
        "bytes",
        "characters",
        "delimiter",
        "fields",
        "output-delimiter",
    ],
    ..none()
};
const EXPAND: Spec = Spec {
    valued: "t",
    valued_longs: &["tabs"],
    ..none()
};
const UNIQ: Spec = Spec {
    valued: "fsw",
    valued_longs: &[
        "skip-fields",
        "skip-chars",
        "check-chars",
        "group",
        "all-repeated",
    ],
    ..none()
};
const CMP: Spec = Spec {
    valued: "ni",
    valued_longs: &["bytes", "ignore-initial"],
    ..none()
};
const OD: Spec = Spec {
    valued: "AjNtSwv",
    valued_longs: &[
        "address-radix",
        "skip-bytes",
        "read-bytes",
        "format",
        "strings",
        "width",
    ],
    ..none()
};
const XXD: Spec = Spec {
    valued: "cglosn",
    ..none()
};
const HEXDUMP: Spec = Spec {
    valued: "nseL",
    files: "f",
    valued_longs: &["length", "skip", "format", "color"],
    file_longs: &["format-file"],
    ..none()
};
const STRINGS: Spec = Spec {
    valued: "nTte",
    valued_longs: &["bytes", "target", "encoding", "radix"],
    ..none()
};
const BASE64: Spec = Spec {
    valued: "w",
    valued_longs: &["wrap"],
    ..none()
};
const BAT: Spec = Spec {
    valued: "lLHrm",
    valued_longs: &[
        "language",
        "theme",
        "style",
        "paging",
        "pager",
        "wrap",
        "tabs",
        "color",
        "decorations",
        "line-range",
        "highlight-line",
        "map-syntax",
        "terminal-width",
        "file-name",
        "diff-context",
    ],
    ..none()
};
// The first operand is the program, unless `-e` or `-f` gives it; `-f FILE`
// is a program file.
const AWK: Spec = Spec {
    valued: "Fv",
    valued_longs: &["field-separator", "assign"],
    files: "f",
    file_longs: &["file"],
    pattern: true,
    given: "f",
    given_longs: &["file"],
    ..none()
};
const SED: Spec = Spec {
    valued: "el",
    valued_longs: &["expression", "line-length"],
    files: "f",
    file_longs: &["file"],
    pattern: true,
    given: "ef",
    given_longs: &["expression", "file"],
    ..none()
};
// `tar -cf out.tar dir`, `-C dir`, `-T list`: every other operand is read.
const TAR: Spec = Spec {
    valued: "CILbNVgHKs",
    valued_longs: &[
        "directory",
        "use-compress-program",
        "blocking-factor",
        "transform",
        "strip-components",
        "owner",
        "group",
        "label",
        "exclude",
        "level",
        "newer",
    ],
    files: "fTX",
    file_longs: &["file", "files-from", "exclude-from"],
    ..none()
};
const ARCHIVE: Spec = Spec {
    valued: "STMbBo",
    valued_longs: &["suffix", "threads", "memlimit", "output"],
    files: "D",
    file_longs: &["dictionary"],
    ..none()
};
const ZIP: Spec = Spec {
    valued: "bnPtTOsF",
    ..none()
};
const GPG: Spec = Spec {
    valued: "ruRoz",
    valued_longs: &[
        "recipient",
        "local-user",
        "output",
        "homedir",
        "passphrase",
        "cipher-algo",
        "digest-algo",
        "compress-algo",
        "default-key",
        "keyring",
        "status-fd",
        "logger-fd",
    ],
    file_longs: &["passphrase-file"],
    ..none()
};

/// The places a program opens to show or pass on what is in them, for the
/// programs that [`path_args`] does not know because `effect` does not call
/// them reads-only: `None` for any other program. `more` and the
/// compressors only read what they are given; `awk`, `sed` and `tar` take
/// their program or their archive first.
pub(crate) fn extra_paths<'a>(unit: &'a Unit, key: &str) -> Option<Vec<Cow<'a, Arg>>> {
    let args = unit.args.as_slice();
    let spec: &Spec = match (unit.shell, key) {
        (Shell::Posix, "tac") => &TAC,
        (Shell::Posix, "rev" | "more" | "most" | "comm") => &NONE,
        (Shell::Posix, "nl") => &NL,
        (Shell::Posix, "fold") => &FOLD,
        (Shell::Posix, "paste") => &PASTE,
        (Shell::Posix, "cut") => &CUT,
        (Shell::Posix, "expand" | "unexpand") => &EXPAND,
        (Shell::Posix, "uniq") => &UNIQ,
        (Shell::Posix, "cmp") => &CMP,
        (Shell::Posix, "od") => &OD,
        (Shell::Posix, "xxd") => &XXD,
        (Shell::Posix, "hexdump" | "hd") => &HEXDUMP,
        (Shell::Posix, "strings") => &STRINGS,
        (Shell::Posix, "base64" | "base32" | "basenc") => &BASE64,
        (Shell::Posix, "bat" | "batcat") => &BAT,
        (Shell::Posix, "awk" | "gawk" | "mawk" | "nawk") => &AWK,
        (Shell::Posix, "sed") => &SED,
        (Shell::Posix, "tar") => {
            // Old style: `tar cf out.tar dir` has its options in the first
            // word, with no dash.
            let old = args
                .first()
                .and_then(Arg::known)
                .is_some_and(|first| !first.starts_with('-'));
            return Some(paths_of(args.get(usize::from(old)..)?, &TAR).places);
        }
        (
            Shell::Posix,
            "gzip" | "gunzip" | "zcat" | "gzcat" | "bzip2" | "bunzip2" | "bzcat" | "xz" | "unxz"
            | "xzcat" | "zstd" | "unzstd" | "zstdcat" | "lz4" | "brotli",
        ) => &ARCHIVE,
        (Shell::Posix, "zip") => &ZIP,
        (Shell::Posix, "7z" | "7za" | "7zz") => &NONE,
        (Shell::Posix, "gpg" | "gpg2") => &GPG,
        _ => return None,
    };
    Some(paths_of(args, spec).places)
}

/// The places `openssl` reads: the file after `-in`, `-inkey`, `-key`,
/// `-keyfile`, `-cert`, `-certfile`, `-CAfile` and `-passin file:`; its
/// options have one dash.
pub(crate) fn openssl_paths(args: &[Arg]) -> Vec<Cow<'_, Arg>> {
    let mut paths = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.known() {
            Some("-in" | "-inkey" | "-key" | "-keyfile" | "-cert" | "-certfile" | "-CAfile") => {
                paths.extend(iter.next().map(Cow::Borrowed));
            }
            Some("-passin" | "-passout") => {
                if let Some(next) = iter.next() {
                    match next.known().map(|text| text.strip_prefix("file:")) {
                        Some(Some(file)) => paths.push(Cow::Owned(Arg::Known(file.to_string()))),
                        Some(None) => {}
                        None => paths.push(Cow::Borrowed(next)),
                    }
                }
            }
            _ => {}
        }
    }
    paths
}

/// What the operands of a `git` command name that it reads: the same as
/// [`path_args`] gives, without the folder `-C` names, which git only looks in.
pub(crate) fn git_reads(args: &[Arg]) -> Vec<Cow<'_, Arg>> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("-C") => at += 2,
            Some("--no-pager" | "-P" | "--no-optional-locks") => at += 1,
            _ => break,
        }
    }
    let Some(subcommand) = args.get(at).and_then(Arg::known) else {
        return Vec::new();
    };
    let rest = args.get(at + 1..).unwrap_or_default();
    git::read(subcommand, rest)
        .into_iter()
        .flat_map(|reading| reading.paths)
        .collect()
}

/// What a unit opens: the places its program names, and what [`reach`] needs
/// to know about how it was given them.
#[derive(Default)]
pub(super) struct Opened<'a> {
    /// Every place the program opens: its operands, and the values of the
    /// options that take a file.
    pub(super) places: Vec<Cow<'a, Arg>>,
    /// How many of them are operands, the places it searches or lists: a file
    /// an option names (`grep -f words.txt`) is not one.
    pub(super) operands: usize,
    /// For `git`, the operands that are revisions and pathspecs, which git
    /// takes inside the work tree and the guard does not read as places.
    pub(super) pathspecs: Vec<&'a Arg>,
    /// For `git`, the folders `-C` names, in order: each is relative to the
    /// one before it.
    pub(super) dirs: Vec<&'a Arg>,
}

/// The arguments of `unit` that are places its program opens, and the places
/// that switches name (`findstr /F:file`), which are not whole arguments.
fn path_args<'a>(unit: &'a Unit, key: &str) -> Opened<'a> {
    let args = unit.args.as_slice();
    if takes_no_paths(unit.shell, key) {
        return Opened::default();
    }
    if key == "git" {
        return git_paths(args);
    }
    let paths = match (unit.shell, key) {
        (Shell::Posix, "ls") => paths_of(args, &LS),
        (Shell::Posix, "cat") => paths_of(args, &none()),
        (Shell::Posix, "wc") => paths_of(args, &WC),
        (Shell::Posix, "head") => paths_of(args, &HEAD),
        (Shell::Posix, "tail") => paths_of(args, &TAIL),
        (Shell::Posix, "stat") => paths_of(args, &STAT),
        (Shell::Posix, "du") => paths_of(args, &DU),
        (Shell::Posix, "df") => paths_of(args, &DF),
        (Shell::Posix, "realpath") => paths_of(args, &REALPATH),
        (Shell::Posix, "diff") => paths_of(args, &DIFF),
        (Shell::Posix, "sort") => paths_of(args, &SORT),
        (Shell::Posix, "file") => paths_of(args, &FILE),
        (Shell::Posix, "less") => paths_of(args, &LESS),
        (Shell::Posix, "grep" | "egrep" | "fgrep") => paths_of(args, &GREP),
        (Shell::Posix, "rg") => paths_of(args, &RG),
        (Shell::Posix, "fd") => paths_of(args, &FD),
        (Shell::Posix, "find") => borrowed(find_starts(args)),
        (Shell::PowerShell, _) => borrowed(powershell_paths(key, args)),
        (Shell::Cmd, _) => cmd_paths(key, args),
        // A reader this table has no entry for: every argument.
        _ => borrowed(args.iter().collect()),
    };
    paths
}

/// The places a program opens as the table says, for the rule about reading
/// a key: the same table [`operands`] judges and `reach` reads.
pub(crate) fn path_places<'a>(unit: &'a Unit, key: &str) -> Vec<Cow<'a, Arg>> {
    path_args(unit, key).places
}

fn borrowed(args: Vec<&Arg>) -> Opened<'_> {
    Opened {
        operands: args.len(),
        places: args.into_iter().map(Cow::Borrowed).collect(),
        ..Opened::default()
    }
}

/// The places a cmd program names. `findstr` takes switches with `/` or `-`
/// and runs letters together after one prefix, the one with a value last
/// (`/smf:file`, `-if:file`); `/s/b` is two runs. Three of its switches name
/// files: `/F:file` is a list of files to open, which the guard never sees, so
/// it is `Unknown` whatever it names; `/G:file` holds the search strings and
/// `/D:dir;dir` the folders to search, and their values are places. `/C:string`
/// and `/A:attr` are data. With `/G:` or `/C:` every operand is a file;
/// without either, the first operand is what to search for. A run with a letter
/// `findstr` does not know, or a value switch that is not last, is `Unknown`.
/// `dir` has `/`-switches that are all data (`/A:`, `/O:`, `/T:`) and `type`
/// has none. A value known only when it runs, or an operand that is, is an
/// operand, and so a place.
fn cmd_paths<'a>(key: &str, args: &'a [Arg]) -> Opened<'a> {
    let mut paths = Vec::new();
    let mut operands: Vec<&Arg> = Vec::new();
    let findstr = key == "findstr";
    let mut given = false;
    let unknown = || Cow::Owned(Arg::Unknown("a switch the guard does not read".to_string()));
    for arg in args {
        let text = arg.known();
        if findstr {
            match text.map(findstr_switch) {
                Some(Switch::Run { value, text }) => {
                    given |= matches!(value, Some('c' | 'g'));
                    match (value, text) {
                        (Some('g'), Some(text)) => {
                            paths.push(Cow::Owned(Arg::Known(text.to_string())));
                        }
                        (Some('d'), Some(text)) => paths.extend(
                            text.split(';')
                                .map(|folder| Cow::Owned(Arg::Known(folder.to_string()))),
                        ),
                        (Some('f'), _) => paths.push(unknown()),
                        _ => {}
                    }
                    continue;
                }
                Some(Switch::Unread) => {
                    paths.push(unknown());
                    continue;
                }
                Some(Switch::Operand) | None => {}
            }
        } else if text.and_then(switches).is_some() {
            continue;
        }
        operands.push(arg);
    }
    // The first operand is what to search for, when it is known: one known
    // only when it runs could be a switch.
    if findstr
        && !given
        && operands
            .first()
            .is_some_and(|first| first.known().is_some())
    {
        operands.remove(0);
    }
    let count = operands.len();
    paths.extend(operands.into_iter().map(Cow::Borrowed));
    Opened {
        places: paths,
        operands: count,
        ..Opened::default()
    }
}

/// What an argument of `findstr` is.
enum Switch<'a> {
    /// Not a switch: `//server/share`, a lone `-`, a name.
    Operand,
    /// A switch run the guard does not read.
    Unread,
    /// A switch run read, and the switch in it that takes a value (`a`, `c`,
    /// `d`, `f`, `g`), with the value.
    Run {
        value: Option<char>,
        text: Option<&'a str>,
    },
}

/// A `findstr` argument read as the switches it is: `/` or `-`, then letters
/// of `findstr`'s switches (`B E L R S I X V N M O P`, `OFF`, `OFFLINE`, and
/// `A C D F G`, which take `:value`, the last letter only); `/` also
/// separates runs (`/s/b`).
fn findstr_switch(text: &str) -> Switch<'_> {
    let slash = text.starts_with('/');
    let Some(body) = text
        .strip_prefix('/')
        .or_else(|| text.strip_prefix('-'))
        .filter(|body| !body.is_empty())
    else {
        return Switch::Operand;
    };
    let (names, text) = match body.split_once(':') {
        Some((names, value)) => (names, Some(value)),
        None => (body, None),
    };
    let runs: Vec<&str> = if slash {
        names.split('/').collect()
    } else {
        vec![names]
    };
    if runs.iter().any(|run| run.is_empty()) {
        return Switch::Operand;
    }
    let mut value = None;
    for (at, run) in runs.iter().enumerate() {
        let lower = run.to_ascii_lowercase();
        if matches!(lower.as_str(), "off" | "offline") {
            continue;
        }
        for (place, letter) in lower.char_indices() {
            let last = at + 1 == runs.len() && place + letter.len_utf8() == lower.len();
            match letter {
                'b' | 'e' | 'l' | 'r' | 's' | 'i' | 'x' | 'v' | 'n' | 'm' | 'o' | 'p' => {}
                'a' | 'c' | 'd' | 'f' | 'g' if last => value = Some(letter),
                _ => return Switch::Unread,
            }
        }
    }
    // A value given to a run that ends in a switch that takes none, or a
    // switch that takes one given none.
    if text.is_some() != value.is_some() {
        return Switch::Unread;
    }
    Switch::Run { value, text }
}

/// A cmd switch run for a program other than `findstr`: the names of `/s/b`
/// or `/A:d`, and the value after the first `:`. `None` for what is not one,
/// such as `//server/share`.
fn switches(text: &str) -> Option<(Vec<&str>, Option<&str>)> {
    let body = text.strip_prefix('/')?;
    let (names, value) = match body.split_once(':') {
        Some((names, value)) => (names, Some(value)),
        None => (body, None),
    };
    let list: Vec<&str> = names.split('/').collect();
    list.iter()
        .all(|name| !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '?'))
        .then_some((list, value))
}

/// The places a `find` searches: its arguments before the first test or
/// action, after its own options.
fn find_starts(args: &[Arg]) -> Vec<&Arg> {
    let mut at = 0;
    while let Some(text) = args.get(at).and_then(Arg::known) {
        match text {
            "-H" | "-L" | "-P" => at += 1,
            "-D" | "-O" => at += 2,
            text if text.starts_with("-O") && text.len() > 2 => at += 1,
            _ => break,
        }
    }
    args.get(at..)
        .unwrap_or_default()
        .iter()
        .take_while(|arg| {
            !arg.known()
                .is_some_and(|text| text.starts_with('-') || text == "(" || text == "!")
        })
        .collect()
}

/// The places a `git` command names: the folder of `-C`, and what its
/// reading subcommand names (see [`git::read`]). The other operands are
/// revisions and pathspecs inside the work tree, which git does not take
/// outside it, and are not read as places.
fn git_paths(args: &[Arg]) -> Opened<'_> {
    let mut opened = Opened::default();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("-C") => {
                opened.dirs.extend(args.get(at + 1));
                at += 2;
            }
            Some("--no-pager" | "-P" | "--no-optional-locks") => at += 1,
            _ => break,
        }
    }
    if let Some(subcommand) = args.get(at).and_then(Arg::known) {
        let rest = args.get(at + 1..).unwrap_or_default();
        if let Some(reading) = git::read(subcommand, rest) {
            opened.places.extend(reading.paths);
            opened.pathspecs = reading.operands;
        }
    }
    opened
}

/// The places a PowerShell cmdlet names: `-Path` and `-LiteralPath` (of
/// `Get-ChildItem`, `Get-Item`, `Get-Content`, `Select-String`, `Test-Path`
/// and `Resolve-Path`), `Resolve-Path -RelativeBasePath`, and the positional
/// arguments (the first, for `Select-String`, is the pattern). The other
/// parameters of these name no place: `-Filter`, `-Include`, `-Exclude`,
/// `-Stream` (a stream's name), `-Encoding`, `-Delimiter`, `-Tail`,
/// `-TotalCount`, `-Pattern`, `-PathType`, `-OlderThan`. None writes.
fn powershell_paths<'a>(key: &str, args: &'a [Arg]) -> Vec<&'a Arg> {
    let params = Params::read(args);
    let mut paths = params.values(&["path", "literalpath", "relativebasepath"]);
    let searching = matches!(key, "select-string" | "sls");
    let pattern = params.values(&["pattern"]);
    let skip = usize::from(searching && pattern.is_empty());
    // `Get-ChildItem` takes `-Depth` and `-Attributes` with a value, which is
    // no place. The shared parameter table does not know them (a name there
    // would swallow the target of a `Remove-Item -Depth ~`), so a value that
    // follows one, and is a number or an attribute's name, is left out here.
    let swallowed: Vec<&Arg> = if key == "get-childitem" {
        args.windows(2)
            .filter(|pair| listing_parameter(&pair[0]) && listing_value(&pair[1]))
            .map(|pair| &pair[1])
            .collect()
    } else {
        Vec::new()
    };
    paths.extend(
        params
            .positional
            .iter()
            .skip(skip)
            .copied()
            .filter(|arg| !swallowed.iter().any(|value| std::ptr::eq(*value, *arg))),
    );
    paths
}

/// Whether `arg` is `-Depth` or `-Attributes`, or an abbreviation of either
/// that no other parameter of `Get-ChildItem` shares (two letters at least).
fn listing_parameter(arg: &Arg) -> bool {
    let Some(name) = arg.known().and_then(|text| text.strip_prefix('-')) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    name.len() >= 2
        && !name.contains(':')
        && ("depth".starts_with(&name) || "attributes".starts_with(&name))
}

/// Whether `arg` can be the value of `-Depth` or `-Attributes` and nothing
/// else: a number, or attribute names (`Hidden`, `!System`, `Hidden+System`)
/// with no separator, drive or dot in them.
fn listing_value(arg: &Arg) -> bool {
    arg.known().is_some_and(|text| {
        !text.is_empty()
            && (text.chars().all(|c| c.is_ascii_digit())
                || text
                    .chars()
                    .all(|c| c.is_ascii_alphabetic() || matches!(c, '!' | '+' | ',')))
    })
}

/// One argument read for its flag: what is known of it up to the first
/// expansion, and whether anything after that is unknown.
pub(super) fn shape(arg: &Arg) -> Option<(&str, bool)> {
    match arg {
        Arg::Known(text) => Some((text, false)),
        Arg::Template { text, .. } => {
            let at = text.find(crate::posix::OPAQUE).unwrap_or(text.len());
            Some((&text[..at], true))
        }
        Arg::Unknown(_) | Arg::Input | Arg::Null => None,
    }
}

/// The arguments of a program that are places: its operands, and the values
/// of the options that take a file. What a valued option takes that is not
/// a place, or a pattern, is left out when it is known or its expansions
/// are quoted: an unquoted one could split into more arguments, options
/// among them, and counts as an operand.
fn paths_of<'a>(args: &'a [Arg], spec: &Spec) -> Opened<'a> {
    let mut paths: Vec<Cow<'a, Arg>> = Vec::new();
    let mut operands: Vec<&Arg> = Vec::new();
    let mut given = false;
    let mut options = true;
    let mut iter = args.iter();
    let known = |text: &str| Cow::Owned(Arg::Known(text.to_string()));
    while let Some(arg) = iter.next() {
        let flag =
            shape(arg).filter(|(head, _)| options && head.starts_with('-') && head.len() > 1);
        let Some((head, tail)) = flag else {
            operands.push(arg);
            continue;
        };
        if head == "--" && !tail {
            options = false;
            continue;
        }
        if let Some(long) = head.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            // `--name$x`: the name itself is not known.
            if tail && value.is_none() {
                operands.push(arg);
                continue;
            }
            given |= spec.given_longs.contains(&name);
            if spec.list_longs.contains(&name) {
                paths.push(Cow::Owned(Arg::Unknown(head.to_string())));
                if value.is_none() {
                    iter.next();
                }
            } else if spec.file_longs.contains(&name) {
                match value {
                    // An unknown value is the argument itself; a known one
                    // is judged as the place it is.
                    Some(_) if tail => paths.push(Cow::Borrowed(arg)),
                    Some(value) => paths.push(known(value)),
                    None => paths.extend(taken(iter.next(), true)),
                }
            } else if value.is_some() {
                if tail && !inert(arg) {
                    paths.push(Cow::Borrowed(arg));
                }
            } else if spec.valued_longs.contains(&name) {
                paths.extend(taken(iter.next(), false));
            }
            continue;
        }
        let bundle = &head[1..];
        for (at, letter) in bundle.char_indices() {
            let rest = &bundle[at + letter.len_utf8()..];
            let attached = !rest.is_empty() || tail;
            given |= spec.given.contains(letter);
            if spec.lists.contains(letter) {
                paths.push(Cow::Owned(Arg::Unknown(head.to_string())));
                if !attached {
                    iter.next();
                }
                break;
            }
            if spec.files.contains(letter) {
                if tail {
                    paths.push(Cow::Borrowed(arg));
                } else if attached {
                    paths.push(known(rest));
                } else {
                    paths.extend(taken(iter.next(), true));
                }
                break;
            }
            if spec.valued.contains(letter) {
                if attached {
                    if tail && !inert(arg) {
                        paths.push(Cow::Borrowed(arg));
                    }
                } else {
                    paths.extend(taken(iter.next(), false));
                }
                break;
            }
        }
    }
    if spec.pattern && !given && !operands.is_empty() {
        let pattern = operands.remove(0);
        if !inert(pattern) {
            paths.push(Cow::Borrowed(pattern));
        }
    }
    let count = operands.len();
    paths.extend(operands.into_iter().map(Cow::Borrowed));
    Opened {
        places: paths,
        operands: count,
        ..Opened::default()
    }
}

/// A PowerShell bare word with its quotes taken off as PowerShell takes them:
/// `--contents="\\evil\s"` reaches the program as `--contents=\\evil\s`. A
/// doubled quote inside quotes of its kind is one; a backtick escapes the next
/// character. A word whose quotes do not close is left as written.
pub(super) fn unquoted(text: &str) -> String {
    let mut value = String::with_capacity(text.len());
    let mut quote: Option<char> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None | Some('"'), '`') => value.extend(chars.next()),
            (None, '"' | '\'') => quote = Some(c),
            (Some(open), c) if c == open => {
                if chars.peek() == Some(&open) {
                    value.push(open);
                    chars.next();
                } else {
                    quote = None;
                }
            }
            (_, c) => value.push(c),
        }
    }
    if quote.is_some() {
        text.to_string()
    } else {
        value
    }
}

/// Whether a word that an option would take as its value starts with `-`, so
/// that a mislisted option could swallow a real one: such a line is `Unknown`.
/// A number (`head -n -5`) and a lone `-` are values.
pub(super) fn dashed(arg: &Arg) -> bool {
    shape(arg).is_some_and(|(head, _)| {
        head.starts_with('-') && head != "-" && !head[1..].chars().all(|c| c.is_ascii_digit())
    })
}

/// What an option takes from the next word, as a place to judge: nothing
/// when the word is data that is known or quoted (unless `file` says it names
/// one), and an unreadable place when it starts with `-`.
fn taken(next: Option<&Arg>, file: bool) -> Option<Cow<'_, Arg>> {
    let value = next?;
    if dashed(value) {
        return Some(Cow::Owned(Arg::Unknown(value.text().to_string())));
    }
    (file || !inert(value)).then_some(Cow::Borrowed(value))
}

/// Whether the value of `arg` is only data: known, or with every expansion
/// inside double quotes, where it stays one word.
pub(super) fn inert(arg: &Arg) -> bool {
    match arg {
        Arg::Known(_) => true,
        Arg::Template { source, .. } => expansions(source).iter().all(|found| found.quoted),
        Arg::Unknown(_) | Arg::Input | Arg::Null => false,
    }
}

/// An expansion in the spelling of an argument.
struct Expansion {
    /// The variable, for `$name` and `${name}`; `None` for anything else
    /// (`$(…)`, `${x:-y}`, a backtick, `$1`).
    name: Option<String>,
    /// Whether it stands inside double quotes.
    quoted: bool,
}

/// The expansions in `source`, outside single quotes and not escaped.
fn expansions(source: &str) -> Vec<Expansion> {
    let chars: Vec<char> = source.chars().collect();
    let (mut single, mut double) = (false, false);
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        at += 1;
        if single {
            single = c != '\'';
            continue;
        }
        match c {
            '\\' => at += 1,
            '\'' if !double => single = true,
            '"' => double = !double,
            '`' => found.push(Expansion {
                name: None,
                quoted: double,
            }),
            '$' => {
                let word = |from: usize| -> String {
                    chars
                        .get(from..)
                        .unwrap_or_default()
                        .iter()
                        .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                        .collect()
                };
                let other = Expansion {
                    name: None,
                    quoted: double,
                };
                match chars.get(at).copied() {
                    Some('{') => {
                        let name = word(at + 1);
                        let length = name.chars().count();
                        if !name.is_empty() && chars.get(at + 1 + length) == Some(&'}') {
                            at += length + 2;
                            found.push(Expansion {
                                name: Some(name),
                                quoted: double,
                            });
                        } else {
                            found.push(other);
                        }
                    }
                    Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                        let name = word(at);
                        at += name.chars().count();
                        found.push(Expansion {
                            name: Some(name),
                            quoted: double,
                        });
                    }
                    Some('(' | '\'' | '"') => found.push(other),
                    Some(c) if c.is_ascii_digit() || "@*#?$!-".contains(c) => {
                        at += 1;
                        found.push(other);
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    found
}

// A `for` loop over words written out.

/// The units that a loop's body held, for each of the `bindings` around the
/// unit, with every combination of the words put in place of the variables:
/// a copy of the unit for each one, as if the body were written out. `None`
/// when nothing the unit has refers to a variable, or there are too many
/// combinations to read.
pub(crate) fn substituted(unit: &Unit, enclosing: &[&Binding]) -> Option<Vec<Unit>> {
    /// The most combinations of words read for one unit.
    const LIMIT: usize = 64;
    if enclosing.is_empty() || enclosing.len() > 3 {
        return None;
    }
    let combinations = enclosing
        .iter()
        .try_fold(1_usize, |count, binding| {
            count.checked_mul(binding.words.len())
        })
        .filter(|count| *count <= LIMIT)?;
    let mut copies = Vec::with_capacity(combinations);
    let mut chosen = vec![0_usize; enclosing.len()];
    loop {
        let pairs: Vec<(&str, &str)> = enclosing
            .iter()
            .zip(&chosen)
            .filter_map(|(binding, &word)| {
                Some((binding.variable.as_str(), binding.words.get(word)?.as_str()))
            })
            .collect();
        let mut changed = false;
        let args: Vec<Arg> = unit
            .args
            .iter()
            .map(|arg| {
                substitute(arg, &pairs).map_or_else(
                    || arg.clone(),
                    |value| {
                        changed = true;
                        value
                    },
                )
            })
            .collect();
        if !changed {
            return None;
        }
        copies.push(Unit {
            args,
            ..unit.clone()
        });
        // The next combination, as an odometer.
        let mut place = 0;
        loop {
            let Some(digit) = chosen.get_mut(place) else {
                return Some(copies);
            };
            *digit += 1;
            if enclosing
                .get(place)
                .is_some_and(|binding| *digit < binding.words.len())
            {
                break;
            }
            *digit = 0;
            place += 1;
        }
    }
}

/// `arg` with the loop variables in `pairs` replaced by their words, when
/// every expansion in it is one of them and the rest is its text; `None`
/// when it holds none, or any other.
fn substitute(arg: &Arg, pairs: &[(&str, &str)]) -> Option<Arg> {
    let word = |name: &str| {
        pairs
            .iter()
            .find(|(variable, _)| *variable == name)
            .map(|(_, word)| *word)
    };
    match arg {
        Arg::Unknown(source) => {
            let found = expansions(source);
            let [only] = found.as_slice() else {
                return None;
            };
            let name = only.name.as_deref()?;
            let alone = *source == format!("${name}") || *source == format!("${{{name}}}");
            word(name)
                .filter(|_| alone)
                .map(|word| Arg::Known(word.to_string()))
        }
        Arg::Template { text, source } => {
            let found = expansions(source);
            let pieces: Vec<&str> = text.split(crate::posix::OPAQUE).collect();
            if found.is_empty() || pieces.len() != found.len() + 1 {
                return None;
            }
            let mut value = String::new();
            for (piece, expansion) in pieces.iter().zip(&found) {
                value.push_str(piece);
                value.push_str(word(expansion.name.as_deref()?)?);
            }
            value.push_str(pieces.last()?);
            Some(Arg::Known(value))
        }
        Arg::Known(_) | Arg::Input | Arg::Null => None,
    }
}
