//! The rule about reading a key or a credential: a program the guard knows
//! opens a file's contents, or a `<` redirect, and the file is a place core
//! marks `Secret` (or a disk, or what the kernel serves), the answers the
//! file guard gives a read of the same path.
//!
//! What a program opens is the operand table `effect` keeps (see
//! [`crate::effect::operands`]), with the programs that show or pass on what
//! they open but are not reads-only (`base64`, `cp`, `tar`, `awk`).
//! A file known only when the line runs is not judged: the answer for it is
//! `effect`'s `Unknown`.

use std::borrow::Cow;

use super::files::{remote, rsync_operands};
use super::{listed, sources_and_destination, Checker, COPY_VALUED};
use crate::brace::{braces, spelled_out};
use crate::effect::{operands as table, received};
use crate::powershell::Params;
use crate::unit::{has_flag, option_values, plain, Arg, Split, Unit};
use crate::{Rule, Shell};

impl Checker<'_> {
    /// A file a `<` redirect reads: `base64 < ~/.ssh/id_rsa`, `< file`.
    pub(super) fn redirected_read(&mut self, at: usize) {
        let split = self.split;
        if let Some(read) = split.reads.get(at) {
            let scope = Scope {
                shell: read.shell,
                dir: read.dir.as_ref(),
                hidden: read.hidden,
            };
            // In a `for` over words written out, with each word in place of
            // the variable: as a unit whose one argument is the target.
            let enclosing: Vec<_> = split
                .bindings
                .iter()
                .filter(|binding| binding.reads.contains(&at))
                .collect();
            if enclosing.is_empty() {
                self.secret_in(&scope, &read.target, &read.target, Reach::default());
                return;
            }
            let target = Unit::new(
                read.shell,
                Arg::Known(String::new()),
                vec![read.target.clone()],
                None,
            );
            match table::substituted(&target, &enclosing) {
                Some(copies) => {
                    for copy in &copies {
                        if let Some(each) = copy.args.first() {
                            self.secret_in(&scope, each, &read.target, Reach::default());
                        }
                    }
                }
                None => self.secret_in(&scope, &read.target, &read.target, Reach::default()),
            }
        }
    }

    /// A file PowerShell is given as the program: `. FILE` dot-sources it and
    /// `& FILE` runs it, so it reads what is in the file.
    pub(super) fn called(&mut self, unit: &Unit) {
        if unit.shell != Shell::PowerShell {
            return;
        }
        let scope = Scope {
            shell: unit.shell,
            dir: unit.dir.as_ref(),
            hidden: unit.hidden,
        };
        match &unit.program {
            Arg::Known(program) if program.contains(['/', '\\']) => {
                self.secret_in(&scope, &unit.program, &unit.program, Reach::default());
            }
            // A bare `$HOME\.ssh\id_rsa`, which the grammar cannot read into,
            // spelled out.
            Arg::Unknown(source) => {
                if let Some(path) = crate::powershell::bare_path(source, self.split) {
                    let spelled = Arg::Known(path);
                    self.secret_in(&scope, &spelled, &unit.program, Reach::default());
                }
            }
            _ => {}
        }
    }

    /// The files a unit's program opens to show or pass on, when one is a
    /// key or a credential. `at` is the unit's place in the split, to find
    /// the `for` loops around it.
    pub(super) fn secrets(&mut self, at: usize, unit: &Unit, key: &str) {
        // Only the programs that open a file's contents are looked into: a
        // listing or a check of metadata (`ls`, `stat`, `test -f`) names a
        // file without reading it.
        if !opens(unit.shell, key) {
            return;
        }
        // A file named under a folder only known when it runs is read by
        // its name (`cat "$x/.env"`).
        let named = super::named(unit);
        let unit: &Unit = &named;
        let split = self.split;
        // A `for` over words written out is read with each word in place of
        // its variable, as if the body were written out.
        let enclosing: Vec<_> = split
            .bindings
            .iter()
            .filter(|binding| binding.units.contains(&at))
            .collect();
        match table::substituted(unit, &enclosing) {
            Some(copies) => {
                for copy in &copies {
                    self.opened_by(copy, key);
                }
            }
            None => self.opened_by(unit, key),
        }
    }

    fn opened_by(&mut self, unit: &Unit, key: &str) {
        // As the program receives them (PowerShell takes quotes off a word,
        // a POSIX shell spells a brace list out into more words).
        let unit = received(unit);
        let spelled;
        let unit: &Unit = match spelled_args(&unit, self.split, self.resolver.wild_links()) {
            Some(args) => {
                spelled = Unit {
                    args,
                    ..Unit::clone(&unit)
                };
                &spelled
            }
            None => &unit,
        };
        let places = opened(unit, key);
        let scope = Scope {
            shell: unit.shell,
            dir: unit.dir.as_ref(),
            hidden: unit.hidden,
        };
        // `find -exec` runs the program for each file it finds, so a place
        // it names stands for what is under it.
        let found = unit.wrappers.iter().any(|wrapper| wrapper == "find");
        let own = Reach {
            recursive: found || recursive(unit, key),
            found,
            follows: crate::effect::follows_links(unit, key),
        };
        for place in places {
            match place.as_ref() {
                Arg::Input => {
                    let (handed, down) = self.handed(unit);
                    let reach = Reach {
                        recursive: own.recursive || down.is_some(),
                        found: found || down == Some(true),
                        follows: own.follows,
                    };
                    for each in handed {
                        self.secret_in(&scope, &each, &place, reach);
                    }
                }
                other => self.secret_in(&scope, other, other, own),
            }
        }
    }

    /// Judge one place a read lands on, and add the finding. `written` is
    /// the argument it came from (what a pipeline handed on is not one).
    fn secret_in(&mut self, scope: &Scope<'_>, arg: &Arg, written: &Arg, reach: Reach) {
        let name = super::named_in_unknown_folder(arg);
        let arg = name.as_ref().unwrap_or(arg);
        // Most words are one path as written.
        let spelled;
        let each: &[Arg] = if one_path(arg, scope.shell) {
            std::slice::from_ref(arg)
        } else {
            spelled = {
                let mut spelled = candidates(arg, scope.shell, self.split);
                // A link the caller named may be named with braces, and a
                // quoted word is that name.
                if self.resolver.wild_links()
                    && arg.known().is_some_and(|text| text.contains('{'))
                    && !spelled.contains(arg)
                {
                    spelled.push(arg.clone());
                }
                spelled
            };
            &spelled
        };
        for candidate in each {
            let words = self
                .resolver
                .secret(scope.dir, candidate, scope.shell, scope.hidden);
            if let Some(words) = words {
                self.add(Rule::ReadSecret, format!("reads {words}"), Some(written));
                return;
            }
            // Through more links than any system follows, a link the caller
            // could not read, or past the work a line may spend: the read is
            // of a place the line does not show.
            if self.resolver.lost(scope.dir, candidate, scope.shell) {
                self.add(
                    Rule::Unknown,
                    "reads a path only known when it runs".to_string(),
                    Some(written),
                );
                return;
            }
            // A folder read all the way down holds what is in it: the home
            // directory, a folder holding it, the root of the disk.
            if reach.recursive {
                let parent = match (candidate, reach.found) {
                    (Arg::Known(text), true) => Arg::Known(format!("{text}/..")),
                    _ => candidate.clone(),
                };
                let holds = [candidate, &parent].into_iter().find_map(|folder| {
                    self.resolver.holder(
                        scope.dir,
                        folder,
                        scope.shell,
                        scope.hidden,
                        reach.follows,
                    )
                });
                if let Some(words) = holds {
                    self.add(
                        Rule::ReadSecret,
                        format!("reads {words}, and the keys in it"),
                        Some(written),
                    );
                    return;
                }
            }
        }
    }

    /// What the stage before `unit` hands it: the places a listing found,
    /// through any stage that only selects or orders them, and whether the
    /// listing went all the way down (`Some(true)`: the places are entries
    /// of the folders it searched, as `find` lists them). Nothing when the stage is not one of
    /// those (a pipeline of text is not a list of paths).
    fn handed(&self, unit: &Unit) -> (Vec<Arg>, Option<bool>) {
        let mut at = unit.stage;
        while let Some(stage) = at.filter(|stage| stage.index > 0) {
            let Some(producer) = self
                .producers
                .get(&(stage.pipeline, stage.index - 1))
                .and_then(|&index| self.split.units.get(index))
            else {
                return (Vec::new(), None);
            };
            if let Some(found) = lister(producer) {
                return (found, lists_down(producer));
            }
            if !table::passes(producer) {
                return (Vec::new(), None);
            }
            at = producer.stage;
        }
        (Vec::new(), None)
    }
}

/// Where a read is made from.
struct Scope<'a> {
    shell: Shell,
    dir: Option<&'a Arg>,
    hidden: bool,
}

/// How far down a place reaches: a program that goes through every folder
/// below the one it is given, and what `find` found (`found`: the place is
/// one of the files it walked to, so the folder it started from is
/// the place's parent).
#[derive(Clone, Copy, Default)]
struct Reach {
    recursive: bool,
    found: bool,
    /// Whether the program opens what it finds through the links it meets
    /// (`grep -R`, `find -L`, `cp -rL`): then a folder holds what the links
    /// below it land on.
    follows: bool,
}

/// Whether the program reads every folder below the ones it is given:
/// `grep -r`, `rg`, `cp -r`, `rsync -a`, `tar`, `zip -r`, `diff -r`; in cmd
/// `findstr /s`, `xcopy /s`, `robocopy /s`; in PowerShell `Copy-Item
/// -Recurse`.
fn recursive(unit: &Unit, key: &str) -> bool {
    let args = unit.args.as_slice();
    match (unit.shell, key) {
        (Shell::Posix, "rg" | "tar") => true,
        (Shell::Posix, "grep" | "egrep" | "fgrep") => {
            has_flag(args, Some('r'), Some("recursive"))
                || has_flag(args, Some('R'), None)
                || has_flag(args, None, Some("dereference-recursive"))
        }
        (Shell::Posix, "cp" | "rsync") => {
            has_flag(args, Some('r'), Some("recursive"))
                || has_flag(args, Some('R'), None)
                || has_flag(args, Some('a'), Some("archive"))
        }
        (Shell::Posix, "diff" | "zip") => has_flag(args, Some('r'), Some("recursive")),
        (Shell::PowerShell, "copy-item") => Params::read(args)
            .named
            .iter()
            .any(|(name, _)| "recurse".starts_with(name.as_str())),
        (Shell::PowerShell | Shell::Cmd, "tar") => true,
        (Shell::PowerShell | Shell::Cmd, "findstr" | "xcopy" | "robocopy") => ["s", "e", "mir"]
            .iter()
            .any(|switch| crate::unit::has_switch(args, switch)),
        _ => false,
    }
}

/// Whether a listing goes through every folder below the places it is given:
/// `Some(true)` when what it hands on is entries of those folders, as `find`
/// does (the folder it started from is the place's parent), `Some(false)`
/// when it hands on the folders themselves; `None` when it lists one level.
fn lists_down(unit: &Unit) -> Option<bool> {
    let args = unit.args.as_slice();
    let down = match (unit.shell, unit.key().as_deref()) {
        (Shell::Posix, Some("find")) => return Some(true),
        (Shell::Posix, Some("fd")) => true,
        (Shell::Posix, Some("ls")) => has_flag(args, Some('R'), Some("recursive")),
        (Shell::PowerShell, Some("get-childitem")) => Params::read(args)
            .named
            .iter()
            .any(|(name, _)| "recurse".starts_with(name.as_str())),
        (Shell::Cmd, Some("dir")) => crate::unit::has_switch(args, "s"),
        _ => false,
    };
    down.then_some(false)
}

/// Whether the program opens the contents of the files it is given, for the
/// rule to look at them. The list is what the guard knows: a program named
/// here and not in `effect`'s table is not reads-only, but it shows or passes
/// on what it opens.
fn opens(shell: Shell, key: &str) -> bool {
    match shell {
        Shell::Posix => matches!(
            key,
            "cat"
                | "head"
                | "tail"
                | "wc"
                | "grep"
                | "egrep"
                | "fgrep"
                | "rg"
                | "diff"
                | "sort"
                | "less"
                | "git"
                | "source"
                | "."
                | "dd"
                | "cp"
                | "install"
                | "rsync"
                | "openssl"
                | "tac"
                | "rev"
                | "more"
                | "most"
                | "comm"
                | "nl"
                | "fold"
                | "paste"
                | "cut"
                | "expand"
                | "unexpand"
                | "uniq"
                | "cmp"
                | "od"
                | "xxd"
                | "hexdump"
                | "hd"
                | "strings"
                | "base64"
                | "base32"
                | "basenc"
                | "bat"
                | "batcat"
                | "awk"
                | "gawk"
                | "mawk"
                | "nawk"
                | "sed"
                | "tar"
                | "gzip"
                | "gunzip"
                | "zcat"
                | "gzcat"
                | "bzip2"
                | "bunzip2"
                | "bzcat"
                | "xz"
                | "unxz"
                | "xzcat"
                | "zstd"
                | "unzstd"
                | "zstdcat"
                | "lz4"
                | "brotli"
                | "zip"
                | "gpg"
                | "gpg2"
                | "7z"
                | "7za"
                | "7zz"
                | "curl"
                | "wget"
        ),
        Shell::PowerShell => matches!(
            key,
            "get-content"
                | "cat"
                | "gc"
                | "type"
                | "select-string"
                | "sls"
                | "import-clixml"
                | "import-csv"
                | "compress-archive"
                | "copy-item"
                | "more"
                | "findstr"
                | "certutil"
                | "tar"
                | "xcopy"
                | "robocopy"
                | "git"
        ),
        Shell::Cmd => matches!(
            key,
            "type"
                | "more"
                | "sort"
                | "findstr"
                | "find"
                | "fc"
                | "comp"
                | "copy"
                | "xcopy"
                | "robocopy"
                | "certutil"
                | "tar"
                | "git"
        ),
    }
}

/// The places the program opens, as the operand table says (see [`opens`]).
fn opened<'u>(unit: &'u Unit, key: &str) -> Vec<Cow<'u, Arg>> {
    let args = unit.args.as_slice();
    match unit.shell {
        Shell::Posix => posix(unit, key, args),
        Shell::PowerShell => powershell(unit, key, args),
        Shell::Cmd => cmd(unit, key, args),
    }
}

fn posix<'u>(unit: &'u Unit, key: &str, args: &'u [Arg]) -> Vec<Cow<'u, Arg>> {
    let borrowed = |args: Vec<&'u Arg>| args.into_iter().map(Cow::Borrowed).collect();
    match key {
        // What a search shows of a file; `rg --files` lists names only.
        "rg" if has_flag(args, None, Some("files")) => Vec::new(),
        "cat" | "head" | "tail" | "wc" | "grep" | "egrep" | "fgrep" | "rg" | "diff" | "sort"
        | "less" => {
            let mut places = table::path_places(unit, key);
            // A search that goes down into folders and is given none is of
            // the working directory, unless a pipeline gives it its text.
            if places.is_empty() && recursive(unit, key) && !from_pipe(unit) {
                places.push(Cow::Owned(Arg::Known(".".to_string())));
            }
            places
        }
        // A work tree's files, and what an option or `--no-index` names;
        // the folder `-C` names is only looked in.
        "git" => {
            let mut places = table::git_reads(args);
            places.extend(git_objects(args));
            places
        }
        // `source FILE` runs what the file holds.
        "source" | "." => args.first().map(Cow::Borrowed).into_iter().collect(),
        "dd" => args
            .iter()
            .filter_map(|arg| arg.known()?.strip_prefix("if="))
            .map(|file| Cow::Owned(Arg::Known(file.to_string())))
            .collect(),
        // The sources of a copy are read whatever the destination is.
        "cp" | "install" => borrowed(sources_and_destination(args, &COPY_VALUED, unit.shell).0),
        "rsync" => {
            let operands = rsync_operands(args);
            match operands.split_last() {
                Some((_, sources)) if !sources.is_empty() => {
                    borrowed(sources.iter().copied().filter(|arg| !remote(arg)).collect())
                }
                _ => Vec::new(),
            }
        }
        "openssl" => table::openssl_paths(args),
        // `curl file:///etc/shadow` reads the file it names, and `-K` the
        // file it takes its options from.
        "curl" => args
            .iter()
            .filter_map(|arg| file_url(arg.known()?))
            .map(|path| Cow::Owned(Arg::Known(path)))
            .chain(config_files(key, args).into_iter().map(Cow::Owned))
            .collect(),
        // wget reads its options from `--config`, and the addresses it
        // fetches from `-i` (`--input-file`).
        "wget" => config_files(key, args)
            .into_iter()
            .map(Cow::Owned)
            .collect(),
        _ => table::extra_paths(unit, key).unwrap_or_default(),
    }
}

/// The files `curl` and `wget` take their options or addresses from:
/// curl's `-K` (`--config`), wget's `--config` and `-i` (`--input-file`), as a word of their own,
/// after `=`, attached or at the end of a cluster of flags (`-sK f`,
/// `-qi f`); `-` is the input.
pub(super) fn config_files(key: &str, args: &[Arg]) -> Vec<Arg> {
    let mut files = option_files(key, args);
    if key != "curl" {
        files.extend(option_values(
            args,
            "i",
            &["input-file"],
            super::send::WGET_VALUES,
        ));
    }
    files.retain(|file| file.known() != Some("-"));
    files
}

/// The files `curl` and `wget` take options from that the line does not
/// show: curl's `-K` (`--config`), wget's `--config`.
pub(super) fn option_files(key: &str, args: &[Arg]) -> Vec<Arg> {
    let mut files = if key == "curl" {
        option_values(args, "K", &["config"], super::send::CURL_VALUES)
    } else {
        option_values(args, "", &["config"], super::send::WGET_VALUES)
    };
    files.retain(|file| file.known() != Some("-"));
    files
}

/// The files of the repository's history git shows by their path: `show`,
/// `cat-file` and `grep`'s `REV:path` (`HEAD:.env`, `:.env` for the index),
/// read from the working directory as git reads a `./` path, and the file
/// `blame` names. A secret there is in the history as it is in the work
/// tree.
fn git_objects(args: &[Arg]) -> Vec<Cow<'_, Arg>> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.known() {
            Some("-C" | "-c") => at += 2,
            Some(text) if text.starts_with('-') => at += 1,
            _ => break,
        }
    }
    let Some(subcommand) = args.get(at).and_then(Arg::known) else {
        return Vec::new();
    };
    let rest = args.get(at + 1..).unwrap_or_default();
    let mut words = rest
        .iter()
        .filter_map(Arg::known)
        .filter(|text| !text.starts_with('-'));
    match subcommand {
        "show" | "cat-file" | "grep" => words
            .filter(|text| !text.contains("://"))
            .filter_map(|text| text.split_once(':'))
            .map(|(_, path)| path.strip_prefix("./").unwrap_or(path))
            .filter(|path| !path.is_empty())
            .map(|path| Cow::Owned(Arg::Known(path.to_string())))
            .collect(),
        "blame" | "annotate" => words
            .next_back()
            .map(|path| Cow::Owned(Arg::Known(path.to_string())))
            .into_iter()
            .collect(),
        _ => Vec::new(),
    }
}

fn powershell<'u>(unit: &'u Unit, key: &str, args: &'u [Arg]) -> Vec<Cow<'u, Arg>> {
    if key == "git" {
        let mut places = table::git_reads(args);
        places.extend(git_objects(args));
        return places;
    }
    if key == "copy-item" {
        let params = Params::read(args);
        let mut operands = params.values(&["path", "literalpath"]);
        operands.extend(params.positional.iter().copied());
        // `-Path` is position 0 and `-Destination` position 1, so with no
        // `-Destination` the last operand is the destination.
        if params.values(&["destination"]).is_empty() && operands.len() > 1 {
            operands.pop();
        }
        if operands.is_empty() && from_pipe(unit) {
            return vec![Cow::Owned(Arg::Input)];
        }
        return operands.into_iter().map(Cow::Borrowed).collect();
    }
    let places = table::path_places(unit, key);
    // A cmdlet given no path of its own opens what the pipeline hands it.
    if places.is_empty() && table::binds_pipeline(key) && from_pipe(unit) {
        return vec![Cow::Owned(Arg::Input)];
    }
    places
}

fn cmd<'u>(unit: &'u Unit, key: &str, args: &'u [Arg]) -> Vec<Cow<'u, Arg>> {
    match key {
        "git" => table::git_reads(args),
        // `copy a+b dest`, and `copy a dest`: every operand but the last is
        // read; one alone is copied to the working directory.
        "copy" | "xcopy" => {
            let operands = split_operands(&plain(args));
            let sources = match operands.split_last() {
                Some((_, sources)) if !sources.is_empty() => sources,
                _ => operands.as_slice(),
            };
            sources.iter().cloned().map(Cow::Owned).collect()
        }
        // The folder it copies from comes first.
        "robocopy" => plain(args)
            .into_iter()
            .take(1)
            .map(|arg| Cow::Owned(arg.clone()))
            .collect(),
        // What `find` searches for comes first.
        "find" => args
            .iter()
            .skip_while(|arg| arg.known().is_some_and(|t| t.starts_with('/')))
            .skip(1)
            .map(Cow::Borrowed)
            .collect(),
        // A hash shows nothing of what it hashes.
        "certutil"
            if args.iter().filter_map(Arg::known).any(|text| {
                matches!(
                    text.to_ascii_lowercase().as_str(),
                    "-hashfile" | "/hashfile"
                )
            }) =>
        {
            Vec::new()
        }
        // `findstr` takes switches of its own, which the table reads.
        "findstr" => table::path_places(unit, key),
        // Any other word may be a path: `type /dev/sda` is not a switch, and a
        // switch (`/s`) is no place a secret is at.
        _ => args.iter().map(Cow::Borrowed).collect(),
    }
}

/// The path a `file:` URL names, for a program that opens it:
/// `file:///etc/shadow`, `file://localhost/etc/shadow` and `file:/etc/shadow`
/// are `/etc/shadow`. A word may be the URL or hold it after an `=`
/// (`--url=file://...`). `$HOME` in it is already `~` (`file://$HOME/.ssh/x`),
/// which is the home directory as in a plain path.
fn file_url(text: &str) -> Option<String> {
    let value = text.split_once('=').map(|(_, value)| value);
    [Some(text), value].into_iter().flatten().find_map(|url| {
        let rest = url
            .get(..5)
            .filter(|scheme| scheme.eq_ignore_ascii_case("file:"))
            .map(|_| &url[5..])?;
        let rest = rest.strip_prefix("//").unwrap_or(rest);
        let path = rest.strip_prefix("localhost").unwrap_or(rest);
        path.starts_with(['/', '~']).then(|| path.to_string())
    })
}

/// cmd's `copy` ends an operand at `,`, `;` and `=`, and joins files with `+`.
fn split_operands(args: &[&Arg]) -> Vec<Arg> {
    args.iter()
        .flat_map(|arg| match arg {
            Arg::Known(text) => text
                .split([',', ';', '=', '+'])
                .filter(|part| !part.is_empty())
                .map(|part| Arg::Known(part.to_string()))
                .collect::<Vec<_>>(),
            other => vec![(*other).clone()],
        })
        .collect()
}

/// Whether a PowerShell cmdlet given no path works on its pipeline input.
fn from_pipe(unit: &Unit) -> bool {
    unit.stage.is_some_and(|stage| stage.index > 0)
}

/// What a listing hands on, as places: `ls ~/.ssh`, `find ~/.ssh`, `fd`,
/// `git ls-files`, `Get-ChildItem`.
fn lister(unit: &Unit) -> Option<Vec<Arg>> {
    if let Some(found) = listed(unit) {
        return Some(found);
    }
    let key = unit.key()?;
    let places = match key.as_str() {
        // What a line writes out as words is a list of paths when a reader
        // is handed it (`echo ~/.ssh/id_rsa | xargs cat`); a word the guard
        // cannot place is no finding.
        "echo" if unit.shell == Shell::Posix => {
            let words = unit.args.iter().skip_while(|arg| {
                arg.known().is_some_and(|text| {
                    text.len() > 1
                        && text.starts_with('-')
                        && text[1..].chars().all(|c| matches!(c, 'n' | 'e' | 'E'))
                })
            });
            return Some(words.cloned().collect());
        }
        "printf" if unit.shell == Shell::Posix => {
            return Some(unit.args.iter().skip(1).cloned().collect());
        }
        "write-output" | "echo" if unit.shell == Shell::PowerShell => {
            let params = Params::read(&unit.args);
            return Some(params.positional.into_iter().cloned().collect());
        }
        "fd" if unit.shell == Shell::Posix => table::path_places(unit, "fd"),
        "git" if table::lists(unit) => table::git_reads(&unit.args),
        _ => return None,
    };
    let mut found: Vec<Arg> = places.into_iter().map(Cow::into_owned).collect();
    if found.is_empty() {
        found.push(Arg::Known(".".to_string()));
    }
    Some(found)
}

/// Whether a word is the one path it is written as: no brace list, no `~name`,
/// no partly known value.
fn one_path(arg: &Arg, shell: Shell) -> bool {
    shell != Shell::Posix
        || matches!(arg, Arg::Known(text)
            if !text.contains('{')
                && (!text.starts_with('~') || text == "~" || text.starts_with("~/")))
}

/// The paths an argument can be, for the places to be judged: itself; a brace
/// list in a POSIX shell (`~/.ssh/{id_rsa,x}`) spelled out; another user's
/// home directory (`~alice/.ssh/id_rsa`) wherever a system keeps one; or the
/// folder a word is under when it only ends in something known when the line
/// runs (`~/.ssh/$f`), which lands in that folder whatever `$f` is.
fn candidates(arg: &Arg, shell: Shell, split: &Split) -> Vec<Arg> {
    if shell != Shell::Posix {
        return vec![arg.clone()];
    }
    let listed: Vec<Arg> = match arg {
        Arg::Unknown(source) if source.contains(['{', '\'']) => {
            braces(source, split).unwrap_or_default()
        }
        Arg::Known(text) if text.contains('{') => words(text).unwrap_or_else(|| vec![arg.clone()]),
        Arg::Template { text, .. } => {
            let known = text
                .find(crate::posix::OPAQUE)
                .map_or(text.as_str(), |at| &text[..at]);
            if known.ends_with('/') {
                vec![Arg::Known(known.to_string())]
            } else {
                Vec::new()
            }
        }
        other => vec![other.clone()],
    };
    listed.into_iter().flat_map(homes).collect()
}

/// The arguments of a unit in a POSIX shell with each brace list spelled out
/// into the words it makes, which is what the program is given (`cp
/// ~/.ssh/id_rsa{,.bak} /tmp` has three operands, not two); `None` when none
/// has one.
fn spelled_args(unit: &Unit, split: &Split, literal: bool) -> Option<Vec<Arg>> {
    let braced = |arg: &Arg| match arg {
        Arg::Known(text) => text.contains('{'),
        Arg::Unknown(source) => source.contains(['{', '\'']),
        Arg::Template { .. } | Arg::Input | Arg::Null => false,
    };
    if unit.shell != Shell::Posix || !unit.args.iter().any(braced) {
        return None;
    }
    let mut changed = false;
    let mut args = Vec::with_capacity(unit.args.len());
    for arg in &unit.args {
        let list = match arg {
            Arg::Unknown(source) => braces(source, split),
            Arg::Known(text) => words(text),
            Arg::Template { .. } | Arg::Input | Arg::Null => None,
        };
        // A list that makes no word is read as the word it is written as.
        match list.filter(|list| !list.is_empty()) {
            Some(list) => {
                changed = true;
                // With a link named, a word with braces is also the name it
                // spells: a link may be named so, and a quoted word is that
                // name.
                if literal && matches!(arg, Arg::Known(_)) && !list.contains(arg) {
                    args.push(arg.clone());
                }
                args.extend(list);
            }
            None => args.push(arg.clone()),
        }
    }
    changed.then_some(args)
}

/// The words a POSIX word stands for when the shell spells a brace list in
/// it out (`~/.ssh/id_rsa{,.pub}` is `~/.ssh/id_rsa` and
/// `~/.ssh/id_rsa.pub`), as the read rule reads them: for a sender handed
/// one. `None` for a word with none, and for a list too big to spell out.
pub(super) fn brace_words(arg: &Arg, split: &Split) -> Option<Vec<Arg>> {
    let list = match arg {
        Arg::Known(text) if text.contains('{') => words(text),
        Arg::Unknown(source) if source.contains(['{', '\'']) => braces(source, split),
        _ => None,
    }?;
    (!list.is_empty() && list.as_slice() != std::slice::from_ref(arg)).then_some(list)
}

/// The words a brace list in `text`, a word whose quotes are off, stands for:
/// a brace in it is read as a bare one, as the shell reads `{a,b}`.
fn words(text: &str) -> Option<Vec<Arg>> {
    let chars: Vec<(char, bool)> = text.chars().map(|c| (c, true)).collect();
    spelled_out(&chars).map(|found| found.into_iter().map(Arg::Known).collect())
}

/// `~alice/.ssh/id_rsa` as the paths it can be: the user's home directory is
/// `/home/alice` or `/Users/alice`, and the root user's is `/root` or
/// `/var/root`, as core reads them. Any other word is itself.
fn homes(arg: Arg) -> Vec<Arg> {
    let Arg::Known(text) = &arg else {
        return vec![arg];
    };
    let Some(user) = text.strip_prefix('~') else {
        return vec![arg];
    };
    let (name, rest) = user.split_once('/').unwrap_or((user, ""));
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return vec![arg];
    }
    let mut folders = vec![format!("/home/{name}"), format!("/Users/{name}")];
    if name == "root" {
        folders.extend(["/root".to_string(), "/var/root".to_string()]);
    }
    folders
        .into_iter()
        .map(|folder| Arg::Known(format!("{folder}/{rest}")))
        .collect()
}
