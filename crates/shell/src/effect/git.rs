//! The options of the git subcommands that only read, and which of them name
//! a file.
//!
//! Each subcommand lists the options it knows are reading ones; any other
//! option is `Unknown`, since a new option could write, run a program or open
//! a file the guard cannot name (git refuses abbreviated long options, so a
//! name matches exactly). An option in the list that takes a file is judged
//! as a place, where a value known only when it runs is `Unknown`.

use std::borrow::Cow;

use super::operands::inert;
use super::Effect;
use crate::unit::Arg;

/// The options a subcommand knows as reading ones.
struct Opts {
    /// Long options that take no value, or one attached with `=`, as groups so
    /// that `log`, `diff` and `show` share what they share. A leading `no-`
    /// is taken off when the name itself is not listed.
    flags: &'static [&'static [&'static str]],
    /// Long options whose value is data (a revision, a pattern, a number):
    /// attached or the next argument.
    valued: &'static [&'static str],
    /// Long options whose value is a file, attached or the next argument.
    files: &'static [&'static str],
    /// Short options that stand alone, in a bundle or with digits after
    /// (`-5`, `-M90`).
    shorts: &'static str,
    /// Short options whose value is data, attached or the next argument.
    short_valued: &'static str,
    /// Short options whose value is a file.
    short_files: &'static str,
}

/// What `diff`, `show` and `log` print about a change.
const DIFF: &[&str] = &[
    "stat",
    "numstat",
    "shortstat",
    "dirstat",
    "cumulative",
    "summary",
    "patch",
    "patch-with-raw",
    "patch-with-stat",
    "raw",
    "name-only",
    "name-status",
    "check",
    "compact-summary",
    "full-index",
    "binary",
    "text",
    "minimal",
    "patience",
    "histogram",
    "diff-algorithm",
    "renames",
    "find-renames",
    "find-copies",
    "find-copies-harder",
    "break-rewrites",
    "irreversible-delete",
    "ignore-space-change",
    "ignore-all-space",
    "ignore-space-at-eol",
    "ignore-blank-lines",
    "ignore-cr-at-eol",
    "inter-hunk-context",
    "unified",
    "abbrev",
    "color",
    "color-words",
    "color-moved",
    "word-diff",
    "word-diff-regex",
    "diff-filter",
    "relative",
    "function-context",
    "src-prefix",
    "dst-prefix",
    "line-prefix",
    "default-prefix",
    "no-ext-diff",
    "no-textconv",
    "ita-invisible-in-index",
    "ws-error-highlight",
    "submodule",
    "ignore-submodules",
    "stat-width",
    "stat-name-width",
    "stat-count",
    "stat-graph-width",
    "output-indicator-new",
    "output-indicator-old",
    "output-indicator-context",
    "exit-code",
    "quiet",
    "cc",
    "combined-all-paths",
    "diff-merges",
    "remerge-diff",
];

/// What `log` and `show` walk and how they show a commit.
const WALK: &[&str] = &[
    "oneline",
    "graph",
    "all",
    "branches",
    "tags",
    "remotes",
    "decorate",
    "abbrev-commit",
    "reverse",
    "merges",
    "merge",
    "first-parent",
    "follow",
    "full-history",
    "simplify-merges",
    "simplify-by-decoration",
    "sparse",
    "dense",
    "ancestry-path",
    "topo-order",
    "date-order",
    "author-date-order",
    "left-right",
    "left-only",
    "right-only",
    "cherry",
    "cherry-pick",
    "cherry-mark",
    "boundary",
    "parents",
    "children",
    "walk-reflogs",
    "relative-date",
    "source",
    "show-signature",
    "notes",
    "standard-notes",
    "show-notes",
    "invert-grep",
    "regexp-ignore-case",
    "extended-regexp",
    "fixed-strings",
    "perl-regexp",
    "all-match",
    "show-pulls",
    "mailmap",
    "use-mailmap",
    "log-size",
    "no-walk",
    "do-walk",
    "expand-tabs",
    "encoding",
    "pretty",
    "format",
    "date",
    "stdin",
    "count",
];

/// The values of `log`'s options that are data.
const LOG_VALUED: &[&str] = &[
    "author",
    "committer",
    "grep",
    "since",
    "until",
    "after",
    "before",
    "max-count",
    "skip",
    "min-parents",
    "max-parents",
    "glob",
    "decorate-refs",
    "decorate-refs-exclude",
    "exclude",
    "grep-reflog",
    "pretty",
    "format",
    "date",
    "encoding",
];

/// `-p -u -q -s -R -w -b -z -a -c -m -i -t -E -F -P -g -M -C -B -l -W` and the
/// digits (`-5`) are alone; `-n`, `-S`, `-G`, `-L` and `-U` take data;
/// `-O` takes a file (the order file of a diff).
const DIFF_SHORTS: &str = "puqsRwbzacmitEFPgMCBlW";

const STATUS: Opts = Opts {
    flags: &[&[
        "short",
        "branch",
        "porcelain",
        "long",
        "verbose",
        "ignored",
        "untracked-files",
        "ignore-submodules",
        "ahead-behind",
        "renames",
        "column",
        "show-stash",
        "find-renames",
        "null",
    ]],
    valued: &[],
    files: &[],
    shorts: "sbvzuM",
    short_valued: "",
    short_files: "",
};

const LOG: Opts = Opts {
    flags: &[DIFF, WALK],
    valued: LOG_VALUED,
    files: &["orderfile"],
    shorts: DIFF_SHORTS,
    short_valued: "nSGLU",
    short_files: "O",
};

const SHOW: Opts = Opts {
    flags: &[DIFF, WALK],
    valued: LOG_VALUED,
    files: &["orderfile"],
    shorts: DIFF_SHORTS,
    short_valued: "nSGLU",
    short_files: "O",
};

const GIT_DIFF: Opts = Opts {
    flags: &[
        DIFF,
        &[
            "cached",
            "staged",
            "merge-base",
            "no-index",
            "ours",
            "theirs",
            "base",
        ],
    ],
    valued: &[],
    files: &["orderfile"],
    shorts: DIFF_SHORTS,
    short_valued: "SGLU",
    short_files: "O",
};

const BLAME: Opts = Opts {
    flags: &[&[
        "incremental",
        "porcelain",
        "line-porcelain",
        "root",
        "show-stats",
        "progress",
        "score-debug",
        "show-name",
        "show-number",
        "show-email",
        "minimal",
        "color-lines",
        "color-by-age",
        "abbrev",
        "first-parent",
        "follow",
    ]],
    valued: &["ignore-rev", "date", "reverse", "encoding"],
    files: &["contents", "ignore-revs-file"],
    shorts: "befnpstwlMC",
    short_valued: "L",
    short_files: "S",
};

const REV_PARSE: Opts = Opts {
    flags: &[&[
        "show-toplevel",
        "show-prefix",
        "show-cdup",
        "git-dir",
        "git-common-dir",
        "absolute-git-dir",
        "is-inside-work-tree",
        "is-inside-git-dir",
        "is-bare-repository",
        "is-shallow-repository",
        "show-superproject-working-tree",
        "abbrev-ref",
        "short",
        "verify",
        "quiet",
        "symbolic",
        "symbolic-full-name",
        "all",
        "branches",
        "tags",
        "remotes",
        "default",
        "not",
        "revs-only",
        "no-revs",
        "flags",
        "no-flags",
        "path-format",
        "show-object-format",
        "local-env-vars",
    ]],
    valued: &["git-path", "since", "until", "after", "before"],
    files: &[],
    shorts: "q",
    short_valued: "",
    short_files: "",
};

const LS_FILES: Opts = Opts {
    flags: &[&[
        "cached",
        "deleted",
        "modified",
        "others",
        "ignored",
        "stage",
        "directory",
        "empty-directory",
        "unmerged",
        "killed",
        "resolve-undo",
        "exclude-standard",
        "error-unmatch",
        "full-name",
        "recurse-submodules",
        "abbrev",
        "eol",
        "sparse",
        "deduplicate",
        "format",
        "with-tree",
    ]],
    valued: &["exclude", "exclude-per-directory"],
    files: &["exclude-from"],
    shorts: "cdmosuktzvf",
    short_valued: "x",
    short_files: "X",
};

fn opts(subcommand: &str) -> Option<&'static Opts> {
    Some(match subcommand {
        "status" => &STATUS,
        "log" => &LOG,
        "show" => &SHOW,
        "diff" => &GIT_DIFF,
        "blame" => &BLAME,
        "rev-parse" => &REV_PARSE,
        "ls-files" => &LS_FILES,
        _ => return None,
    })
}

impl Opts {
    fn flag(&self, name: &str) -> bool {
        let listed = |name: &str| self.flags.iter().any(|group| group.contains(&name));
        listed(name) || name.strip_prefix("no-").is_some_and(listed)
    }
}

/// What reading a subcommand's arguments found: its effect, and the places it
/// names.
pub(super) struct Reading<'a> {
    pub(super) effect: Effect,
    pub(super) paths: Vec<Cow<'a, Arg>>,
}

/// The arguments of `subcommand`, when it is one that only reads. `--output`
/// writes a file. An operand known only when it runs could be an option, so
/// it is `Unknown`; what is known is a revision or a pathspec, which git does
/// not take outside the work tree, except for the operands of `--no-index`,
/// and what follows `--`, which are places.
pub(super) fn read<'a>(subcommand: &str, args: &'a [Arg]) -> Option<Reading<'a>> {
    let opts = opts(subcommand)?;
    let (mut changes, mut unknown, mut no_index) = (false, false, false);
    let mut paths: Vec<Cow<'a, Arg>> = Vec::new();
    let mut operands: Vec<&Arg> = Vec::new();
    let known = |text: &str| Cow::Owned(Arg::Known(text.to_string()));
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (head, tail) = match arg {
            Arg::Known(text) => (text.as_str(), false),
            Arg::Template { text, .. } => (
                &text[..text.find(crate::posix::OPAQUE).unwrap_or(text.len())],
                true,
            ),
            Arg::Unknown(_) | Arg::Input => {
                unknown = true;
                continue;
            }
        };
        if head == "--" && !tail {
            paths.extend(iter.by_ref().map(Cow::Borrowed));
            break;
        }
        if let Some(long) = head.strip_prefix("--") {
            let (name, value) = long
                .split_once('=')
                .map_or((long, None), |(name, value)| (name, Some(value)));
            if tail && value.is_none() {
                unknown = true;
            } else if name == "output" {
                changes = true;
            } else if opts.files.contains(&name) {
                match value {
                    Some(_) if tail => paths.push(Cow::Borrowed(arg)),
                    Some(value) => paths.push(known(value)),
                    None => paths.extend(iter.next().map(Cow::Borrowed)),
                }
            } else if opts.valued.contains(&name) {
                match value {
                    Some(_) => unknown |= tail && !inert(arg),
                    None => unknown |= iter.next().is_some_and(|next| !inert(next)),
                }
            } else if opts.flag(name) {
                no_index |= name == "no-index";
                unknown |= value.is_some() && tail && !inert(arg);
            } else {
                unknown = true;
            }
        } else if let Some(bundle) = head.strip_prefix('-').filter(|bundle| !bundle.is_empty()) {
            for (at, letter) in bundle.char_indices() {
                let rest = &bundle[at + letter.len_utf8()..];
                let attached = !rest.is_empty() || tail;
                if opts.short_files.contains(letter) {
                    if tail {
                        paths.push(Cow::Borrowed(arg));
                    } else if attached {
                        paths.push(known(rest));
                    } else {
                        paths.extend(iter.next().map(Cow::Borrowed));
                    }
                    break;
                }
                if opts.short_valued.contains(letter) {
                    if attached {
                        unknown |= tail && !inert(arg);
                    } else {
                        unknown |= iter.next().is_some_and(|next| !inert(next));
                    }
                    break;
                }
                if !opts.shorts.contains(letter) && !letter.is_ascii_digit() {
                    unknown = true;
                    break;
                }
            }
        } else {
            unknown |= tail;
            operands.push(arg);
        }
    }
    if no_index {
        paths.extend(operands.into_iter().map(Cow::Borrowed));
    }
    let effect = if changes {
        Effect::Changes
    } else if unknown {
        Effect::Unknown
    } else {
        Effect::ReadsOnly
    };
    Some(Reading { effect, paths })
}
