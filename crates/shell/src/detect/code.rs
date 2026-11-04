//! The rules about code a line runs that it does not show: git's own
//! commands and config, awk, expect, `AppleScript`, compiled .NET.

use super::hedged;
use super::Checker;
use crate::launch::{git_global, git_long, is_submodule, Global};
use crate::path::{pattern_folder, within};
use crate::said::Said;
use crate::unit::{could_be, has_flag, may_be_option, operands, unknown_start, Arg, Flagged, Unit};
use crate::{Rule, Shell};
use milo_guards_core::spelling::glob;

impl Checker<'_> {
    /// Git, and code run through awk, expect, `AppleScript` or .NET.
    pub(super) fn code(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let shell = unit.shell;
        match key {
            // Git.
            "git" => {
                self.git(args, shell);
                self.git_work_tree(unit);
            }

            // Code the guard does not read.
            "add-type" => self.add(Rule::Unknown, "compiles and loads code", None),
            "expect" if shell == Shell::Posix => {
                self.add(
                    Rule::Unknown,
                    "runs expect code the guard does not read",
                    None,
                );
            }
            "awk" | "gawk" | "mawk" | "nawk" => self.awk(unit),
            "osascript" => self.add(
                Rule::Unknown,
                "runs AppleScript the guard does not read",
                None,
            ),
            _ => {}
        }
    }

    /// awk code that runs commands (`system(…)`, a pipe) or writes files
    /// (`print > "f"`) is risky; so is code the guard cannot read (`-f script`,
    /// a library `-i` or `@include` loads, a variable), and so is a shared
    /// library `-l` or `@load` loads, native code whatever its name. gawk's
    /// `inplace` library (`-i inplace`) edits each file awk reads, so each
    /// is a write, as is the file `-o`, `-p` or `-d` is given. The options
    /// are read as gawk's `getopt_long` reads them (see [`awk_options`]).
    fn awk(&mut self, unit: &Unit) {
        let args = unit.args.as_slice();
        let read = awk_options(args);
        let mut programs: Vec<Value<'_>> = Vec::new();
        let mut file = false;
        let mut libraries: Vec<Library<'_>> = Vec::new();
        // A shared library `-l` or `@load` loads, with the word that names
        // it when that is only known when it runs.
        let mut extension: Option<Option<&Arg>> = None;
        for &(name, value) in &read.options {
            match name {
                "file" | "exec" => file = true,
                "load" => {
                    let unread = match value {
                        Some(Value::Word(arg)) if arg.known().is_none() => Some(arg),
                        _ => None,
                    };
                    extension = Some(extension.flatten().or(unread));
                }
                "source" => programs.extend(value),
                "include" => libraries.push(value.map_or(Library::Other, library)),
                "dump-variables" | "pretty-print" | "profile" => {
                    if let Some(value) = value {
                        self.write(unit.shell, unit.scope(), &value.arg(), "writes to");
                    }
                }
                _ => {}
            }
        }
        if let Some(arg) = read.unread {
            self.add(
                Rule::Unknown,
                "gives awk an option the guard does not read",
                Some(arg),
            );
        }
        let mut operands = args.get(read.end..).unwrap_or_default();
        if programs.is_empty() && !file {
            if let Some((program, rest)) = operands.split_first() {
                programs.push(Value::Word(program));
                operands = rest;
            }
        }
        if file {
            self.add(
                Rule::Unknown,
                "runs an awk script the guard does not read",
                None,
            );
        }
        for program in programs {
            match program.known() {
                Some(code) => {
                    if awk_runs_commands(code) {
                        self.add(
                            Rule::Unknown,
                            "runs commands or writes files from awk code",
                            None,
                        );
                    }
                    for directive in directives(code) {
                        match directive {
                            Directive::Include(library) => libraries.push(library),
                            Directive::Load => extension = Some(extension.flatten()),
                        }
                    }
                }
                None => self.add(
                    Rule::Unknown,
                    "runs awk code only known when it runs",
                    Some(&program.arg()),
                ),
            }
        }
        if let Some(arg) = extension {
            self.add(
                Rule::Unknown,
                "loads an awk extension the guard does not read",
                arg,
            );
        }
        if libraries.iter().any(|library| *library != Library::InPlace) {
            self.add(
                Rule::Unknown,
                "runs an awk script the guard does not read",
                libraries.iter().find_map(|library| match library {
                    Library::Unread(arg) => Some(*arg),
                    _ => None,
                }),
            );
        }
        let in_place = if libraries.contains(&Library::InPlace) {
            Flagged::Written
        } else if libraries
            .iter()
            .any(|library| matches!(library, Library::Unread(_)))
        {
            Flagged::Unread
        } else {
            Flagged::Absent
        };
        // Each file awk reads, but `-` (its input) and an assignment
        // (`x=1`), which it reads as one.
        self.flagged(in_place, |checker| {
            for operand in operands.iter().filter(|operand| {
                !operand
                    .known()
                    .is_some_and(|text| text == "-" || assigns(text))
            }) {
                checker.write(unit.shell, unit.scope(), operand, "edits");
            }
        });
    }

    /// git's commands that throw work away. An argument only known when it
    /// runs that may be the option that makes one do so (`git push $F
    /// origin main`, `git push "-$F" origin main`, see [`may_be_option`])
    /// is taken as given, and the finding says it may (see [`hedged`]); an
    /// option that keeps work is taken only as written.
    fn git(&mut self, args: &[Arg], shell: Shell) {
        let Global {
            at,
            repository,
            configs,
        } = git_global(args);
        // A `-c` config value that makes git run a command of its own: an
        // alias body starting `!`, or a program git calls (pager, editor,
        // ssh, hooks).
        if configs.iter().any(|config| config_executes(config)) {
            self.add(
                Rule::Unknown,
                "runs a command through git config",
                repository,
            );
        }
        // A subcommand only known when it runs may be any of them, those
        // that throw work away among them (`git $CMD`: `clean -fdx`, `reset
        // --hard`, `push --force`). PowerShell's `"$null"` is an empty
        // string, which git refuses as a subcommand.
        let Some(sub) = args.get(at).filter(|arg| !matches!(arg, Arg::Null)) else {
            return;
        };
        let Some(sub) = sub.known() else {
            self.add(
                Rule::Unknown,
                "runs a git command only known when it runs",
                args.get(at),
            );
            return;
        };
        let rest = &args[at + 1..];
        let flag = |short: Option<char>, long: Option<&str>| git_flag(rest, short, long);
        // Whether an argument only known when it runs may be the option.
        let unread = |short: Option<char>, long: Option<&str>| {
            may_be_option(rest, shell, |start| could_be(start, short, long))
        };
        // `git branch` and `git tag` refuse a delete beside a listing (`-l`,
        // and `-v` for a tag), so with one written, an argument only known
        // when it runs is no delete.
        let lists = flag(Some('l'), Some("list"));
        // `-c clean.requireForce=false` lets `clean` delete without `-f`.
        let force_needless = configs.iter().any(|config| {
            config.split_once('=').is_some_and(|(key, value)| {
                key.eq_ignore_ascii_case("clean.requireforce")
                    && matches!(
                        value.to_ascii_lowercase().as_str(),
                        "false" | "0" | "no" | "off"
                    )
            })
        });
        let operands = operands(rest, &[]);
        let first = operands.first().and_then(|arg| arg.known());
        // What a push that rewrites or deletes says, with `maybe` as below:
        // a force says to lease instead, and a lease alone (`git push
        // --force-with-lease`), which rewrites a branch only when nobody
        // pushed to it since, says so. A lease beside anything that forces,
        // deletes or is only known when it runs is read as a plain force,
        // with no advice: the lease is already written, and leasing a
        // delete still deletes.
        let push = |maybe: bool| -> Said {
            let forces = flag(Some('f'), Some("force"))
                || (maybe && unread(Some('f'), Some("force")))
                || operands.iter().any(|arg| refspec_starts(arg, shell, '+'));
            // Written as the lease, not as `--force`, which git also takes
            // as a prefix of `--force-with-lease` but reads as itself.
            let lease = rest
                .iter()
                .filter_map(Arg::known)
                .take_while(|text| *text != "--")
                .any(|text| text.starts_with("--force-w"));
            let deletes = flag(None, Some("mirror"))
                || flag(Some('d'), Some("delete"))
                || flag(None, Some("prune"))
                || operands.iter().any(|arg| refspec_starts(arg, shell, ':'));
            let leased = lease
                && !unread(Some('f'), Some("force"))
                && !deletes
                && operands.iter().all(|arg| arg.known().is_some());
            if forces {
                if lease || deletes {
                    REWRITES.into()
                } else {
                    Said::instead(REWRITES, "use `git push --force-with-lease`")
                }
            } else if leased {
                "rewrites a branch on the remote unless someone pushed since".into()
            } else {
                REWRITES.into()
            }
        };
        // Whether git's own options move it to another repository, where a
        // dry run typed in this folder would list something else.
        let elsewhere = args[..at].iter().filter_map(Arg::known).any(|text| {
            text == "-C" || text.starts_with("--git-dir") || text.starts_with("--work-tree")
        });
        // What the line does with the options it shows, or, with `maybe`,
        // with an argument only known when it runs taken as an option that
        // throws work away.
        let judge = |maybe: bool| -> Option<(Rule, Said)> {
            let may = |short: Option<char>, long: Option<&str>| {
                flag(short, long) || (maybe && unread(short, long))
            };
            let deletes = |short: Option<char>, long: Option<&str>, listing: bool| {
                flag(short, long) || (maybe && !listing && unread(short, long))
            };
            Some(match sub {
                "reset" if may(None, Some("hard")) => (
                    Rule::GitDiscard,
                    Said::instead("throws away uncommitted changes", STASH_FIRST),
                ),
                "clean"
                    if (force_needless || may(Some('f'), Some("force"))) && !git_dry_run(rest) =>
                {
                    (
                        Rule::GitDiscard,
                        Said::instead(
                            "deletes untracked files",
                            match clean_dry_run(rest) {
                                Some(dry) if !elsewhere => {
                                    format!("list what would go first (`{dry}`)")
                                }
                                _ => CLEAN_SAME.to_string(),
                            },
                        ),
                    )
                }
                "checkout"
                    if may(Some('f'), Some("force"))
                        || rest
                            .iter()
                            .position(|arg| arg.known() == Some("--"))
                            .is_some_and(|dashes| dashes + 1 < rest.len())
                        || operands.iter().any(|arg| arg.known() == Some(".")) =>
                {
                    (Rule::GitDiscard, Said::instead(CHANGES, STASH_FIRST))
                }
                "restore"
                    if !flag(Some('S'), Some("staged")) || may(Some('W'), Some("worktree")) =>
                {
                    (Rule::GitDiscard, Said::instead(CHANGES, STASH_FIRST))
                }
                "switch" if may(None, Some("discard-changes")) || may(Some('f'), Some("force")) => {
                    (Rule::GitDiscard, Said::instead(CHANGES, STASH_FIRST))
                }
                "stash" if matches!(first, Some("drop" | "clear")) => {
                    (Rule::GitDiscard, "deletes stashed changes".into())
                }
                "branch"
                    if deletes(Some('D'), None, lists)
                        || (flag(Some('d'), Some("delete")) && flag(Some('f'), Some("force"))) =>
                {
                    (
                        Rule::GitDiscard,
                        Said::instead(
                            "deletes a branch even if it is not merged",
                            "use `git branch -d`, which keeps a branch that is not merged",
                        ),
                    )
                }
                "push"
                    if may(Some('f'), Some("force"))
                        || flag(None, Some("force-with-lease"))
                        || flag(None, Some("force-if-includes"))
                        || flag(None, Some("mirror"))
                        || flag(Some('d'), Some("delete"))
                        || flag(None, Some("prune"))
                        || operands.iter().any(|arg| forced_refspec(arg, shell)) =>
                {
                    (Rule::GitRemote, push(maybe))
                }
                "filter-branch" | "filter-repo" => {
                    (Rule::GitHistory, "rewrites the repository's history".into())
                }
                "reflog" if matches!(first, Some("expire" | "delete")) => (
                    Rule::GitHistory,
                    "removes what git keeps to undo mistakes".into(),
                ),
                "gc" if (maybe && unread(None, Some("prune")))
                    || rest.iter().filter_map(Arg::known).any(|text| {
                        text.split_once('=').is_some_and(|(name, value)| {
                            matches!(value, "now" | "all") && git_long(name, "prune")
                        })
                    }) =>
                {
                    (
                        Rule::GitHistory,
                        "removes what git keeps to undo mistakes".into(),
                    )
                }
                "config" if config_set_executes(rest) => {
                    let alias = operands
                        .iter()
                        .filter_map(|arg| arg.known())
                        .find(|word| *word != "set")
                        .is_some_and(|key| key.to_ascii_lowercase().starts_with("alias."));
                    if alias {
                        (Rule::Unknown, "sets a git alias that runs a command".into())
                    } else {
                        (
                            Rule::SystemSettings,
                            "sets git config that runs a program".into(),
                        )
                    }
                }
                "update-ref" if may(Some('d'), None) => (Rule::GitDiscard, "deletes a ref".into()),
                // A tag has no reflog to bring it back from.
                "tag"
                    if deletes(
                        Some('d'),
                        Some("delete"),
                        lists || flag(Some('v'), Some("verify")),
                    ) =>
                {
                    (Rule::GitDiscard, "deletes a tag".into())
                }
                // A tag given again by force moves; where it pointed is gone.
                "tag"
                    if flag(Some('f'), Some("force"))
                        && !operands.is_empty()
                        && !flag(Some('l'), Some("list"))
                        && !flag(Some('v'), Some("verify")) =>
                {
                    (
                        Rule::GitDiscard,
                        "moves a tag, losing where it pointed".into(),
                    )
                }
                sub if is_submodule(sub)
                    && first == Some("update")
                    && may(Some('f'), Some("force")) =>
                {
                    (Rule::GitDiscard, "throws away changes in submodules".into())
                }
                sub if is_submodule(sub)
                    && first == Some("deinit")
                    && may(Some('f'), Some("force")) =>
                {
                    (Rule::GitDiscard, "throws away a submodule's changes".into())
                }
                "worktree" if first == Some("remove") && may(Some('f'), Some("force")) => (
                    Rule::GitDiscard,
                    "deletes a worktree with its changes".into(),
                ),
                _ => return None,
            })
        };
        if let Some((rule, said)) = judge(false) {
            self.add(rule, said, repository);
        } else if let Some((rule, said)) = judge(true) {
            let said = Said {
                reason: hedged(&said.reason),
                ..said
            };
            self.add(rule, said, repository);
        }
    }
}

impl Checker<'_> {
    /// git's commands that write files in the work tree from data the line
    /// does not show: `apply` the files a patch names, below the folder git
    /// runs in; `am`, `cherry-pick`, `revert`, `stash apply` and `pop`,
    /// `read-tree -u` and `checkout-index` the files a patch, a commit or
    /// the index holds, anywhere in the work tree; `checkout` and `restore`
    /// given paths the files a revision holds below them. Each may change a
    /// protected path the folder holds (see [`Checker::changes_in`]). The
    /// folder git runs in is `-C`'s, or the one the line is in; the top of
    /// the work tree is the workspace folder that holds it, and is only
    /// known when it runs outside every workspace folder.
    fn git_work_tree(&mut self, unit: &Unit) {
        let args = unit.args.as_slice();
        let shell = unit.shell;
        let Global { at, repository, .. } = git_global(args);
        let Some(sub) = args.get(at).and_then(Arg::known) else {
            return;
        };
        let rest = &args[at + 1..];
        let flag = |short: Option<char>, long: Option<&str>| git_flag(rest, short, long);
        // `--work-tree` moves the work tree where the line may not show.
        let moved = args[..at]
            .iter()
            .any(|arg| arg.text().starts_with("--work-tree"));
        let scope = unit.scope();
        let unknown = || Arg::Unknown("the work tree git is given".to_string());
        let (folder, top) = if moved {
            (unknown(), unknown())
        } else {
            let folder = repository
                .cloned()
                .unwrap_or_else(|| Arg::Known(".".to_string()));
            let top = self
                .resolver
                .workspace_of(scope.dir, &folder, shell)
                .unwrap_or_else(unknown);
            (folder, top)
        };
        let anywhere = match sub {
            "am" => !flag(None, Some("quit")) && !flag(None, Some("show-current-patch")),
            "cherry-pick" | "revert" => !flag(None, Some("quit")),
            "stash" => matches!(rest.first().and_then(Arg::known), Some("apply" | "pop")),
            "read-tree" => flag(Some('u'), None),
            "checkout-index" => !flag(None, Some("temp")),
            _ => false,
        };
        if anywhere {
            let before = self.found.len();
            self.write_folder(shell, scope, &folder, "patches files in");
            if self.found.len() == before {
                self.changes_in(shell, scope, &top);
            }
            return;
        }
        match sub {
            // `--check`, `--stat`, `--numstat` and `--summary` only report,
            // unless `--apply` turns the patching back on.
            "apply"
                if !flag(None, Some("cached"))
                    && (flag(None, Some("apply"))
                        || !(flag(None, Some("check"))
                            || flag(None, Some("stat"))
                            || flag(None, Some("numstat"))
                            || flag(None, Some("summary")))) =>
            {
                self.write_folder(shell, scope, &folder, "patches files in");
            }
            "checkout" | "restore" => {
                if sub == "restore"
                    && flag(Some('S'), Some("staged"))
                    && !flag(Some('W'), Some("worktree"))
                {
                    return;
                }
                // Paths read from a file or the input may be any in the
                // work tree, `:/` among them.
                if flag(None, Some("pathspec-from-file")) {
                    self.changes_in(shell, scope, &top);
                    return;
                }
                for (path, from_top) in pathspecs(sub, rest) {
                    let path = within(Some(if from_top { &top } else { &folder }), &path, shell);
                    self.changes_in(shell, scope, &path);
                }
            }
            _ => {}
        }
    }
}

/// The paths `git checkout` or `git restore` is given, each as the folder
/// it reaches below and whether it starts at the top of the work tree:
/// what follows `--`, or every operand (a revision among them is a name
/// that holds nothing). A pathspec with a wildcard matches at any depth
/// below the folder it starts in, since git's `*` matches `/` too; magic is
/// read as the whole folder, the top of the work tree for `:/` and
/// `:(top)`.
fn pathspecs(sub: &str, rest: &[Arg]) -> Vec<(Arg, bool)> {
    let valued: &[&str] = if sub == "checkout" {
        &["-b", "-B", "--orphan", "--conflict", "--pathspec-from-file"]
    } else {
        &["-s", "--source", "--conflict", "--pathspec-from-file"]
    };
    let dashes = rest.iter().position(|arg| arg.known() == Some("--"));
    let paths: Vec<&Arg> = match dashes {
        Some(at) => rest[at + 1..].iter().collect(),
        None => operands(rest, valued),
    };
    let whole = || Arg::Known(".".to_string());
    paths
        .into_iter()
        .map(|path| match path.known() {
            Some(text) if text.starts_with(":/") || top_magic(text) => (whole(), true),
            Some(text) if text.starts_with(':') => (whole(), false),
            Some(text) if glob::has_wildcard(text) => (Arg::Known(pattern_folder(text)), false),
            _ => (path.clone(), false),
        })
        .collect()
}

/// Whether a pathspec's long magic names `top` (`:(top)x`, `:(glob,top)x`).
fn top_magic(text: &str) -> bool {
    text.strip_prefix(":(")
        .and_then(|magic| magic.split_once(')'))
        .is_some_and(|(magic, _)| {
            magic
                .split(',')
                .any(|word| word.trim().eq_ignore_ascii_case("top"))
        })
}

/// What a push that rewrites or deletes says, when nothing better is known.
const REWRITES: &str = "rewrites or deletes branches on the remote";

/// What to do instead of a `git clean` that deletes, when the dry run
/// cannot be spelled out from the line: it moves git to another repository,
/// or an argument that may be an option is only known when it runs.
const CLEAN_SAME: &str = "list what would go first with `git clean -n` and the same options";

/// What to do instead of throwing changes away.
const STASH_FIRST: &str = "stash the changes first (`git stash`)";

/// What a checkout, restore or switch that throws changes away says.
const CHANGES: &str = "throws away changes to files";

/// Whether a `git push` operand is a refspec that forces (`+main`) or
/// deletes (`:main`) a branch on the remote (see [`refspec_starts`]).
fn forced_refspec(arg: &Arg, shell: Shell) -> bool {
    refspec_starts(arg, shell, '+') || refspec_starts(arg, shell, ':')
}

/// Whether a `git push` operand starts with `start`: written so, or only
/// known when it runs and starting so (`"+$B"`), whatever the rest holds.
fn refspec_starts(arg: &Arg, shell: Shell, start: char) -> bool {
    match arg.known() {
        Some(text) => text.starts_with(start),
        None => unknown_start(arg, shell).is_some_and(|text| text.starts_with(start)),
    }
}

/// The dry run of a `git clean` that deletes: `git clean -n`, with the `-d`,
/// `-x` and `-X` it is given, so it lists what the same clean would delete
/// in its folders and among the ignored files. Its options are read as
/// [`git_dry_run`] reads them: the value of `-e`/`--exclude` is a pattern.
/// `None` when an argument before `--` is only known when it runs, since it
/// may hold a `-d` or `-x` the dry run would then leave out.
fn clean_dry_run(args: &[Arg]) -> Option<String> {
    let mut options = String::from("n");
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        let text = arg.known()?;
        if text == "--" {
            break;
        }
        if text.starts_with("--") {
            if !text.contains('=') && git_long(text, "exclude") {
                words.next();
            }
        } else if let Some(bundle) = text.strip_prefix('-') {
            if !bundle.starts_with(|c: char| c.is_ascii_alphabetic()) {
                continue;
            }
            let (flags, pattern) = bundle.split_once('e').unwrap_or((bundle, ""));
            for short in flags.chars().filter(|c| matches!(c, 'd' | 'x' | 'X')) {
                if !options.contains(short) {
                    options.push(short);
                }
            }
            if bundle.contains('e') && pattern.is_empty() {
                words.next();
            }
        }
    }
    Some(format!("git clean -{options}"))
}

/// A library awk loads with `-i`, `--include` or `@include`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Library<'a> {
    /// gawk's `inplace`, which edits each file awk reads.
    InPlace,
    /// Any other, which the guard does not read.
    Other,
    /// One only known when it runs, which may be either.
    Unread(&'a Arg),
}

/// The library an `-i` value names.
fn library(value: Value<'_>) -> Library<'_> {
    match value {
        Value::Joined(name) => named_library(name),
        Value::Word(arg) => match arg.known() {
            Some(name) => named_library(name),
            None => Library::Unread(arg),
        },
    }
}

/// How a gawk option takes a value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Takes {
    Nothing,
    /// The rest of the word, or else the next word.
    Value,
    /// Only the rest of the word (`-oFILE`, `--profile=FILE`).
    Optional,
}

/// gawk's options as its `getopt_long` table has them: the long name, the
/// letter (none for a space), and how it takes a value.
const AWK_OPTIONS: [(&str, char, Takes); 33] = [
    ("assign", 'v', Takes::Value),
    ("bignum", 'M', Takes::Nothing),
    ("characters-as-bytes", 'b', Takes::Nothing),
    ("copyright", 'C', Takes::Nothing),
    ("csv", 'k', Takes::Nothing),
    ("debug", 'D', Takes::Optional),
    ("dump-variables", 'd', Takes::Optional),
    ("exec", 'E', Takes::Value),
    ("field-separator", 'F', Takes::Value),
    ("file", 'f', Takes::Value),
    ("gen-pot", 'g', Takes::Nothing),
    ("help", 'h', Takes::Nothing),
    ("include", 'i', Takes::Value),
    ("lint", 'L', Takes::Optional),
    ("lint-old", 't', Takes::Nothing),
    ("load", 'l', Takes::Value),
    ("locale", 'Z', Takes::Value),
    ("no-optimize", 's', Takes::Nothing),
    ("non-decimal-data", 'n', Takes::Nothing),
    ("nostalgia", ' ', Takes::Nothing),
    ("optimize", 'O', Takes::Nothing),
    ("parsedebug", 'Y', Takes::Nothing),
    ("persist", ' ', Takes::Optional),
    ("posix", 'P', Takes::Nothing),
    ("pretty-print", 'o', Takes::Optional),
    ("profile", 'p', Takes::Optional),
    ("re-interval", 'r', Takes::Nothing),
    ("sandbox", 'S', Takes::Nothing),
    ("source", 'e', Takes::Value),
    ("trace", 'I', Takes::Nothing),
    ("traditional", 'c', Takes::Nothing),
    ("use-lc-numeric", 'N', Takes::Nothing),
    ("version", 'V', Takes::Nothing),
];

/// An option's value: the rest of its word, or the next word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Value<'a> {
    Joined(&'a str),
    Word(&'a Arg),
}

impl<'a> Value<'a> {
    fn known(self) -> Option<&'a str> {
        match self {
            Self::Joined(text) => Some(text),
            Self::Word(arg) => arg.known(),
        }
    }

    fn arg(self) -> Arg {
        match self {
            Self::Joined(text) => Arg::Known(text.to_string()),
            Self::Word(arg) => arg.clone(),
        }
    }
}

/// What gawk's options say.
#[derive(Default)]
struct AwkOptions<'a> {
    /// Each option given, by its long name, with its value.
    options: Vec<(&'static str, Option<Value<'a>>)>,
    /// The first word that is an option the guard cannot tell: a long one
    /// more than one name starts with, or a `-W` one only known when it
    /// runs.
    unread: Option<&'a Arg>,
    /// Where the operands start: past the options, `--` and `-E`'s file.
    end: usize,
}

/// gawk's options, read as its `getopt_long` reads them up to the first word
/// that is not one (its option list starts with `+`): a bundle one letter
/// at a time (`-bf s.awk`), a letter that takes a value taking the rest of
/// the bundle or else the next word, and one that may take one only the
/// rest; a long option by any prefix only one name starts with
/// (`--incl=inplace`), its value after `=` or in the next word; `-W name`
/// as `--name`. `-E` is the last option gawk reads.
fn awk_options(args: &[Arg]) -> AwkOptions<'_> {
    let mut read = AwkOptions::default();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        let Some(text) = arg.known() else {
            break;
        };
        if text == "--" {
            at += 1;
            break;
        }
        let Some(option) = text.strip_prefix('-').filter(|option| !option.is_empty()) else {
            break;
        };
        at += 1;
        if let Some(long) = option.strip_prefix('-') {
            awk_long(long, arg, args, &mut at, &mut read);
        } else {
            awk_bundle(option, arg, args, &mut at, &mut read);
        }
        if read.options.last().is_some_and(|(name, _)| *name == "exec") {
            break;
        }
    }
    read.end = at.min(args.len());
    read
}

/// The letters of the bundle `bundle` (past its dash), from the word `arg`;
/// a value in the next word is the one at `at`.
fn awk_bundle<'a>(
    bundle: &'a str,
    arg: &'a Arg,
    args: &'a [Arg],
    at: &mut usize,
    read: &mut AwkOptions<'a>,
) {
    for (index, letter) in bundle.char_indices() {
        let rest = &bundle[index + letter.len_utf8()..];
        if letter == 'W' {
            if rest.is_empty() {
                let word = args.get(*at);
                *at += 1;
                match word.map(|word| (word, word.known())) {
                    Some((word, None)) => read.unread = read.unread.or(Some(word)),
                    Some((_, Some(long))) => awk_long(long, arg, args, at, read),
                    None => {}
                }
            } else {
                awk_long(rest, arg, args, at, read);
            }
            return;
        }
        let Some(&(name, _, takes)) = AWK_OPTIONS
            .iter()
            .find(|(_, short, _)| *short == letter && letter != ' ')
        else {
            continue;
        };
        let value = match takes {
            Takes::Nothing => {
                read.options.push((name, None));
                continue;
            }
            Takes::Optional => (!rest.is_empty()).then_some(Value::Joined(rest)),
            Takes::Value if rest.is_empty() => {
                *at += 1;
                args.get(*at - 1).map(Value::Word)
            }
            Takes::Value => Some(Value::Joined(rest)),
        };
        read.options.push((name, value));
        return;
    }
}

/// The long option `text` names (`name` or `name=value`, past its dashes),
/// from the word `arg`; a value in the next word is the one at `at`.
fn awk_long<'a>(
    text: &'a str,
    arg: &'a Arg,
    args: &'a [Arg],
    at: &mut usize,
    read: &mut AwkOptions<'a>,
) {
    let (name, joined) = match text.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (text, None),
    };
    if name.is_empty() {
        return;
    }
    let prefixed: Vec<_> = AWK_OPTIONS
        .iter()
        .filter(|(full, _, _)| full.starts_with(name))
        .collect();
    let found =
        AWK_OPTIONS
            .iter()
            .find(|(full, _, _)| *full == name)
            .or(match prefixed.as_slice() {
                [only] => Some(*only),
                _ => None,
            });
    let Some(&(full, _, takes)) = found else {
        // A prefix more than one name starts with: gawk stops there, and
        // the guard cannot tell which it would have been.
        if prefixed.len() > 1 {
            read.unread = read.unread.or(Some(arg));
        }
        return;
    };
    let value = match (takes, joined) {
        (Takes::Nothing, _) | (Takes::Optional, None) => None,
        (_, Some(value)) => Some(Value::Joined(value)),
        (Takes::Value, None) => {
            *at += 1;
            args.get(*at - 1).map(Value::Word)
        }
    };
    read.options.push((full, value));
}

/// The library `name` is: gawk finds `inplace` as `inplace.awk` in its own
/// folder.
fn named_library(name: &str) -> Library<'static> {
    if matches!(name, "inplace" | "inplace.awk") {
        Library::InPlace
    } else {
        Library::Other
    }
}

/// A directive in awk code: `@include "name"` or `@load "name"`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Directive {
    /// A library `@include` loads.
    Include(Library<'static>),
    /// A shared library `@load` loads.
    Load,
}

/// The directives in awk code, read as gawk's lexer reads them: `@` is a
/// token of its own, and the word after it, past spaces, tabs, carriage
/// returns and backslash-newlines, is a directive when it is `include` or
/// `load`. Only a word made of ASCII letters, digits and `_` is a name, so
/// `@loader` is no directive. An `@include` whose name is not a plain
/// string is a library the guard does not read. A directive is found in a
/// string or regex too, where gawk reads none: risky, not safe.
fn directives(code: &str) -> Vec<Directive> {
    code.split('@')
        .skip(1)
        .filter_map(|after| {
            let after = skip_blanks(after);
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            let (word, rest) = after.split_at(end);
            match word {
                "load" => Some(Directive::Load),
                "include" => Some(Directive::Include(
                    skip_blanks(rest)
                        .strip_prefix('"')
                        .and_then(|name| name.split_once('"'))
                        .map_or(Library::Other, |(name, _)| named_library(name)),
                )),
                _ => None,
            }
        })
        .collect()
}

/// awk code past the blanks gawk's lexer skips between two tokens: spaces,
/// tabs, carriage returns, and a backslash before a newline, with or
/// without a carriage return between.
fn skip_blanks(mut code: &str) -> &str {
    loop {
        let trimmed = code.trim_start_matches([' ', '\t', '\r']);
        match trimmed
            .strip_prefix("\\\n")
            .or_else(|| trimmed.strip_prefix("\\\r\n"))
        {
            Some(rest) => code = rest,
            None => return trimmed,
        }
    }
}

/// Whether an awk operand is an assignment (`x=1`, `ns::x=1`), which awk
/// reads as one and not as a file.
fn assigns(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, _)| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':')
    })
}

/// Whether awk code runs a command or writes a file: `system`, a single
/// `|` (`"cmd" | getline`, `print | "sh"`; `||` is a logical or), or `>`
/// into a quoted file other than `/dev/stdout` or `/dev/stderr`.
fn awk_runs_commands(code: &str) -> bool {
    if code.contains("system") {
        return true;
    }
    let bytes = code.as_bytes();
    bytes.iter().enumerate().any(|(at, &byte)| {
        let before = at
            .checked_sub(1)
            .and_then(|before| bytes.get(before))
            .copied();
        let after = bytes.get(at + 1).copied();
        match byte {
            b'|' => before != Some(b'|') && after != Some(b'|'),
            b'>' if before != Some(b'>') && after != Some(b'=') => code[at + 1..]
                .trim_start_matches('>')
                .trim_start()
                .strip_prefix('"')
                .is_some_and(|target| !target.starts_with("/dev/std")),
            _ => false,
        }
    })
}

/// Whether a git config `key=value` makes git run a command: an alias body
/// starting `!`, or a key whose value git executes.
fn config_executes(config: &str) -> bool {
    let Some((key, value)) = config.split_once('=') else {
        return false;
    };
    let key = key.trim().to_ascii_lowercase();
    if let Some(alias) = key.strip_prefix("alias.") {
        return !alias.is_empty() && value.trim_start().starts_with('!');
    }
    EXEC_CONFIG_KEYS.contains(&key.as_str())
}

/// Whether a `git config KEY VALUE` sets one of those keys.
fn config_set_executes(rest: &[Arg]) -> bool {
    let reads = rest.iter().filter_map(Arg::known).any(|text| {
        matches!(
            text,
            "--get"
                | "--get-all"
                | "--get-regexp"
                | "--get-urlmatch"
                | "--list"
                | "-l"
                | "--unset"
                | "--unset-all"
                | "--remove-section"
                | "--rename-section"
                | "--edit"
                | "-e"
        )
    });
    if reads {
        return false;
    }
    let operands = operands(rest, &["--file", "-f", "--blob", "--type", "--default"]);
    let mut words = operands.iter().filter_map(|arg| arg.known());
    // `git config set KEY VALUE` (git 2.46) or `git config KEY VALUE`; the
    // other subcommands and a key alone only read.
    let (key, value) = match words.next() {
        Some("set") => (words.next(), words.next()),
        Some("get" | "unset" | "list" | "edit" | "rename-section" | "remove-section") => {
            return false;
        }
        key => (key, words.next()),
    };
    match (key, value) {
        (Some(key), Some(value)) => config_executes(&format!("{key}={value}")),
        _ => false,
    }
}

/// git config keys whose value git runs as a command.
const EXEC_CONFIG_KEYS: [&str; 11] = [
    "core.pager",
    "core.editor",
    "core.sshcommand",
    "core.fsmonitor",
    "core.hookspath",
    "core.askpass",
    "sequence.editor",
    "diff.external",
    "credential.helper",
    "gpg.program",
    "uploadpack.packobjectshook",
];

/// Whether `git clean` is left a dry run by its options. git reads them in
/// order, so the last of `-n`, `--dry-run` and `--no-dry-run` wins, each
/// also given as a prefix (`--dry`, `--no-d`); a prefix of `--no-` names
/// several options, so git refuses it, and it is read as a dry run off. The
/// value of `-e`/`--exclude` is not an option: in `-enx` and in `-e -n` the
/// `n` is a pattern.
fn git_dry_run(args: &[Arg]) -> bool {
    let mut dry = false;
    let mut words = args.iter().filter_map(Arg::known);
    while let Some(text) = words.next() {
        if text == "--" {
            break;
        }
        if text.starts_with("--") {
            if git_long(text, "dry-run") {
                dry = true;
            } else if git_long(text, "no-dry-run") {
                dry = false;
            } else if !text.contains('=') && git_long(text, "exclude") {
                words.next();
            }
        } else if let Some(bundle) = text.strip_prefix('-') {
            if !bundle.starts_with(|c: char| c.is_ascii_alphabetic()) {
                continue;
            }
            let (options, pattern) = bundle.split_once('e').unwrap_or((bundle, ""));
            if options.contains('n') {
                dry = true;
            }
            if bundle.contains('e') && pattern.is_empty() {
                words.next();
            }
        }
    }
    dry
}

/// A git option: as [`has_flag`], and also a long option given as a prefix
/// of it, as git takes one (`--h` is `--hard`, see [`git_long`]).
fn git_flag(args: &[Arg], short: Option<char>, long: Option<&str>) -> bool {
    has_flag(args, short, long)
        || long.is_some_and(|long| {
            args.iter()
                .filter_map(Arg::known)
                .take_while(|text| *text != "--")
                .any(|text| git_long(text, long))
        })
}
