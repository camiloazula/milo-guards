//! The rules about archives. One unpacked into a folder is a write into that
//! folder, judged like the destination of `cp`; with no folder given it
//! unpacks into the working directory, and the paths stored in the archive
//! cannot be seen from the line and are not read. One packed with an option
//! that removes what it packs (`tar --remove-files`, `zip -m`, `7z a -sdel`)
//! deletes the members named on the line, judged like the operands of `rm`.

use super::Checker;
use crate::path::within;
use crate::powershell::Params;
use crate::unit::{Arg, Unit};
use crate::Shell;

impl Checker<'_> {
    /// `tar -x`, `unzip`, `7z x`, `Expand-Archive`.
    pub(super) fn unpack(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let folders = match key {
            "tar" | "gtar" | "bsdtar" => tar(args, unit.shell).unpacks_into(),
            "unzip" => unzip(args),
            "7z" | "7za" | "7zr" | "7zz" => seven_zip(args),
            "expand-archive" => Some(expand_archive(args)),
            _ => None,
        };
        for folder in folders.unwrap_or_default() {
            self.write_folder(unit.shell, unit.scope(), &folder, "unpacks into");
        }
    }

    /// `tar -c --remove-files`, `zip -m`, `7z a -sdel`: the program deletes
    /// each file it packs once it has packed it.
    pub(super) fn pack_and_remove(&mut self, unit: &Unit, key: &str) {
        let args = unit.args.as_slice();
        let (members, matched) = match key {
            "tar" | "gtar" | "bsdtar" => (tar(args, unit.shell).removed(), false),
            "zip" => (zip(args), true),
            "7z" | "7za" | "7zr" | "7zz" => (seven_zip_removes(args), true),
            _ => return,
        };
        // `7z` matches a wildcard itself, quoted or not, and so does `zip` on
        // Windows; `zip` on Unix does so only for `-x`, `-i`, `-R` and names inside
        // the archive, so `zip -m x.zip 'a*'` there deletes nothing. A line
        // cannot show which shell's expansion a name went through, so every
        // member is judged with names that start with a dot among the
        // matches: a cautious choice, not how `zip` behaves on Unix.
        self.delete_matching(
            unit,
            &members.iter().collect::<Vec<_>>(),
            "deletes",
            matched,
        );
    }
}

/// Whether `name`, a long option as written, is `full` or a prefix of it of
/// at least `least` letters: GNU tar and bsdtar take a unique prefix.
fn long_option(name: &str, full: &str, least: usize) -> bool {
    name.len() >= least && full.starts_with(name)
}

/// What a `tar` line does, as far as its arguments show.
struct Tar {
    /// Whether it extracts to the disk: `-x`, `--extract`, `--get` and no
    /// other mode and no `-O`; or a mode only known when it runs that no mode
    /// letter rules out.
    unpacks: bool,
    /// Whether `--remove-files` is given to a mode that makes or adds to an
    /// archive (`-c`, `-r`, `-u`), or to one only known when it runs that
    /// no mode letter rules out.
    removes: bool,
    /// The folders `-C`, `--directory` and `--one-top-level` name, in order.
    folders: Vec<Arg>,
    /// The files and folders it is asked to pack, each as seen from where
    /// the line runs (a member after `-C dir` is under `dir`).
    members: Vec<Arg>,
}

impl Tar {
    /// The folders `tar` unpacks into: `-C dir` (`-Cdir`, `--directory dir`,
    /// `--directory=dir`, wherever it stands), or the working directory.
    fn unpacks_into(mut self) -> Option<Vec<Arg>> {
        if !self.unpacks {
            return None;
        }
        if self.folders.is_empty() {
            self.folders.push(Arg::Known(".".to_string()));
        }
        Some(self.folders)
    }

    /// The members `--remove-files` deletes after packing them.
    fn removed(self) -> Vec<Arg> {
        if self.removes {
            self.members
        } else {
            Vec::new()
        }
    }
}

/// The long options of `tar` that take a value, which stands in the next
/// argument when it is not attached with `=`. The ones that name members
/// are read apart, and the one-letter forms are in [`tar`].
const TAR_LONG_VALUES: &[&str] = &[
    "after-date",
    "blocking-factor",
    "checkpoint-action",
    "exclude",
    "exclude-from",
    "exclude-ignore",
    "exclude-ignore-recursive",
    "exclude-tag",
    "exclude-tag-all",
    "exclude-tag-under",
    "file",
    "format",
    "group",
    "group-map",
    "hole-detection",
    "index-file",
    "info-script",
    "label",
    "level",
    "listed-incremental",
    "mode",
    "mtime",
    "new-volume-script",
    "newer",
    "newer-mtime",
    "owner",
    "owner-map",
    "pax-option",
    "quote-chars",
    "quoting-style",
    "record-size",
    "rmt-command",
    "rsh-command",
    "sort",
    "sparse-version",
    "starting-file",
    "strip-components",
    "suffix",
    "tape-length",
    "to-command",
    "transform",
    "use-compress-program",
    "volno-file",
    "warning",
    "xattrs-exclude",
    "xattrs-include",
    "xform",
    "include",
    "options",
    "newer-than",
    "newer-mtime-than",
    "gid",
    "gname",
    "uid",
    "uname",
    "passphrase",
];

/// Long options of `tar` that take none, and that a name could stand for as
/// well as for one that takes a value (`--sparse`, `--checkpoint[=N]`,
/// `--xattrs`; `--inc` is `--incremental` in GNU tar and `--include` in
/// bsdtar; `--mod` is `--mode` in GNU tar, which takes a value, and the only
/// prefix of `--modification-time` in bsdtar, which takes none). A name that
/// may be one of them is read as the flag, which takes no argument: the next
/// one is then a member, the riskier reading.
const TAR_LONG_FLAGS: [&str; 5] = [
    "sparse",
    "checkpoint",
    "xattrs",
    "incremental",
    "modification-time",
];

/// The longest folder, in bytes, that a chain of `-C` is followed to. Each
/// `-C` is joined to the one before it, so a longer chain is a path only
/// known when it runs; that bounds the cost of reading a long line of them.
const TAR_FOLDER_LIMIT: usize = 512;

/// Where `-C folder` moves the members that follow, from where `under` had
/// moved them.
fn moved(under: Option<&Arg>, folder: &Arg, shell: Shell) -> Arg {
    match within(under, folder, shell) {
        Arg::Known(text) if text.len() > TAR_FOLDER_LIMIT => Arg::Unknown(text),
        folder => folder,
    }
}

/// What `tar` is asked to do. A mode that only the line's run shows (`tar
/// "$mode" -f x.tar`) counts as extracting, and as packing.
fn tar(args: &[Arg], shell: Shell) -> Tar {
    // Short options that take a value, whose bundle ends with it.
    const VALUES: &str = "CfbILKNTXFgHV";
    let mut extract = false;
    let mut other_mode = false;
    let mut pack = false;
    let mut to_stdout = false;
    let mut removes_files = false;
    // An argument only known when it runs, which may hold the mode.
    let mut unknown = false;
    let mut folders = Vec::new();
    // Where `-C` moved the members that follow: relative to the line's own
    // folder, and to the `-C` before it.
    let mut under: Option<Arg> = None;
    let mut members = Vec::new();
    let mut iter = args.iter().enumerate();
    while let Some((at, arg)) = iter.next() {
        let Some(text) = arg.known() else {
            unknown |= arg.is_unknown();
            members.push(within(under.as_ref(), arg, shell));
            continue;
        };
        if text == "--" {
            members.extend(
                iter.by_ref()
                    .map(|(_, arg)| within(under.as_ref(), arg, shell)),
            );
            break;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            // Each option may be written as a prefix of it, of at least three
            // letters (`--ext`, `--dir`), as the programs take the unique one.
            let is = |full: &str| long_option(name, full, 3);
            if name == "get" || is("extract") {
                extract = true;
            } else if ["create", "append", "update"].iter().any(|mode| is(mode)) {
                other_mode = true;
                pack = true;
            } else if ["list", "diff", "compare", "delete"]
                .iter()
                .any(|mode| is(mode))
            {
                other_mode = true;
            } else if long_option(name, "to-stdout", 4) {
                to_stdout = true;
            } else if is("remove-files") {
                removes_files = true;
            } else if long_option(name, "one-top-level", 7) {
                folders.extend(attached.map(|folder| Arg::Known(folder.to_string())));
            } else if is("directory") {
                let folder = match attached {
                    Some(folder) => Some(Arg::Known(folder.to_string())),
                    None => iter.next().map(|(_, folder)| folder.clone()),
                };
                if let Some(folder) = folder {
                    under = Some(moved(under.as_ref(), &folder, shell));
                    folders.push(folder);
                }
            } else if is("add-file") {
                // A member, named as the value of the option.
                let member = match attached {
                    Some(member) => Some(Arg::Known(member.to_string())),
                    None => iter.next().map(|(_, member)| member.clone()),
                };
                members.extend(member.map(|member| within(under.as_ref(), &member, shell)));
            } else if long_option(name, "files-from", 5) {
                // The members are in a file the line does not show.
                if attached.is_none() {
                    iter.next();
                }
                members.push(Arg::Unknown("<files from a list>".to_string()));
            } else if attached.is_none()
                && !TAR_LONG_FLAGS.iter().any(|flag| is(flag))
                && TAR_LONG_VALUES.iter().any(|full| is(full))
            {
                iter.next();
            }
            continue;
        }
        // The first argument may be a bundle without a dash: `tar xzf x.tgz`,
        // whose valued letters take the arguments after it, in order.
        let old_style = at == 0 && !text.starts_with('-');
        if !old_style && !text.starts_with('-') {
            members.push(within(under.as_ref(), arg, shell));
            continue;
        }
        let letters = text.strip_prefix('-').unwrap_or(text);
        if !old_style && letters.is_empty() {
            continue;
        }
        for (position, letter) in letters.char_indices() {
            if VALUES.contains(letter) {
                let rest = &letters[position + letter.len_utf8()..];
                let value = if !old_style && !rest.is_empty() {
                    Some(Arg::Known(rest.to_string()))
                } else {
                    iter.next().map(|(_, value)| value.clone())
                };
                match (letter, value) {
                    ('C', Some(folder)) => {
                        under = Some(moved(under.as_ref(), &folder, shell));
                        folders.push(folder);
                    }
                    // The members are in a file the line does not show.
                    ('T', _) => members.push(Arg::Unknown("<files from a list>".to_string())),
                    _ => {}
                }
                if !old_style {
                    break;
                }
                continue;
            }
            match letter {
                'x' => extract = true,
                'c' | 'r' | 'u' => {
                    other_mode = true;
                    pack = true;
                }
                't' | 'A' | 'd' => other_mode = true,
                'O' => to_stdout = true,
                _ => {}
            }
        }
    }
    // With no mode read, an argument that is only known when it runs may be
    // `-x`, or `-c`.
    let mode_unknown = unknown && !other_mode && !extract;
    Tar {
        unpacks: (extract || mode_unknown) && !other_mode && !to_stdout,
        removes: removes_files && (pack || mode_unknown),
        folders,
        members,
    }
}

/// The folder `unzip` unpacks into: `-d dir` (`-ddir`, in a bundle such as
/// `-od dir`), or the working directory. Listing, testing and unpacking to
/// the screen write nothing.
fn unzip(args: &[Arg]) -> Option<Vec<Arg>> {
    let mut folders = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(text) = arg.known() else { continue };
        if text == "--" {
            break;
        }
        let Some(letters) = text.strip_prefix('-').filter(|letters| !letters.is_empty()) else {
            continue;
        };
        for (at, letter) in letters.char_indices() {
            match letter {
                'd' | 'P' => {
                    let rest = &letters[at + 1..];
                    let value = if rest.is_empty() {
                        iter.next().cloned()
                    } else {
                        Some(Arg::Known(rest.to_string()))
                    };
                    if letter == 'd' {
                        folders.extend(value);
                    }
                    break;
                }
                'l' | 'v' | 't' | 'Z' | 'p' | 'c' | 'z' => return None,
                _ => {}
            }
        }
    }
    if folders.is_empty() {
        folders.push(Arg::Known(".".to_string()));
    }
    Some(folders)
}

/// The folders `7z x` and `7z e` unpack into: `-oDIR`, or the working
/// directory.
fn seven_zip(args: &[Arg]) -> Option<Vec<Arg>> {
    let command = args.iter().find_map(|arg| {
        arg.known()
            .filter(|text| !text.starts_with('-'))
            .map(str::to_ascii_lowercase)
    })?;
    if !matches!(command.as_str(), "x" | "e") {
        return None;
    }
    let mut folders = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (text, known) = match arg {
            Arg::Known(text) => (text, true),
            Arg::Unknown(text) | Arg::Template { source: text, .. } => (text, false),
            Arg::Input => continue,
        };
        // Switches are not case-sensitive; `-ao` is another switch.
        let Some(folder) = text
            .get(..2)
            .filter(|prefix| prefix.eq_ignore_ascii_case("-o"))
            .map(|_| &text[2..])
            .filter(|folder| !folder.is_empty())
        else {
            continue;
        };
        // PowerShell reads `-oC:\Windows` as `-oC:` and `\Windows`; the
        // program may get either, so the folder is the two together.
        let folder = match iter.clone().next() {
            Some(rest) if folder.ends_with(':') && known => format!("{folder}{}", rest.text()),
            _ => folder.to_string(),
        };
        folders.push(if known {
            Arg::Known(folder)
        } else {
            Arg::Unknown(folder)
        });
    }
    if folders.is_empty() {
        folders.push(Arg::Known(".".to_string()));
    }
    Some(folders)
}

/// The folder `Expand-Archive` unpacks into: `-DestinationPath`, or the
/// second positional argument (the first when `-Path` is named), or the
/// working directory.
fn expand_archive(args: &[Arg]) -> Vec<Arg> {
    let params = Params::read(args);
    let named = params.values(&["destinationpath"]);
    if let Some(folder) = named.first() {
        return vec![(*folder).clone()];
    }
    let path_named = !params.values(&["path", "literalpath"]).is_empty();
    let folder = params
        .positional
        .get(usize::from(!path_named))
        .map_or_else(|| Arg::Known(".".to_string()), |folder| (*folder).clone());
    vec![folder]
}

/// What the arguments of `zip` after the archive's name stand for, while
/// they are read.
#[derive(Clone, Copy, PartialEq)]
enum ZipList {
    /// Files that stay out (`-x`, `--exclude`).
    Exclude,
    /// Patterns that choose among the files (`-i`, `--include`).
    Include,
}

/// The long options of `zip` that take a value in the next argument.
const ZIP_LONG_VALUES: &[&str] = &[
    "temp-path",
    "suffixes",
    "from-date",
    "before-date",
    "output-file",
    "password",
    "split-size",
    "compression-method",
    "unzip-command",
    "dot-size",
    "logfile-path",
    "unicode",
];

/// The files `zip` deletes after adding them, which `-m` (or `--move`) asks
/// for: the operands after the archive's name, and the names it reads from
/// its input (`-@`). The patterns that follow a bare `-x` stay, up to a lone
/// `@`; those that follow a bare `-i` only choose among the operands, and
/// stand in for them when none is given. `-xpat` and `--exclude=pat` are one
/// value and open no list. An argument that only a run can show, inside a
/// list, may end it (it may start with `-` or be `@`), so the list is
/// closed after it.
fn zip(args: &[Arg]) -> Vec<Arg> {
    let mut moves = false;
    let mut from_input = false;
    let mut positional = Vec::new();
    let mut included = Vec::new();
    let mut list = None;
    let mut options_done = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let option = arg
            .known()
            .filter(|text| !options_done && text.starts_with('-') && text.len() > 1);
        let Some(text) = option else {
            // A lone `@` ends a list and is no operand.
            if list.is_some() && arg.known() == Some("@") {
                list = None;
                continue;
            }
            match list {
                Some(ZipList::Exclude) => {}
                Some(ZipList::Include) => included.push(arg.clone()),
                None => positional.push(arg.clone()),
            }
            // An argument only known when it runs may start with `-` or be
            // a lone `@`, which end the list: the names after it are
            // operands again.
            if list.is_some() && may_be_switch(arg) {
                list = None;
            }
            continue;
        };
        list = None;
        if text == "--" {
            options_done = true;
            continue;
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let is = |full: &str| long_option(name, full, 3);
            if is("move") {
                moves = true;
            } else if is("names-stdin") {
                from_input = true;
            } else if is("exclude") {
                // `--exclude=pat` is the one pattern; a list starts only
                // when nothing is attached.
                list = attached.is_none().then_some(ZipList::Exclude);
            } else if is("include") {
                list = attached.is_none().then_some(ZipList::Include);
            } else if attached.is_none() && ZIP_LONG_VALUES.iter().any(|full| is(full)) {
                iter.next();
            }
            continue;
        }
        let letters = &text[1..];
        let mut before = None;
        for (at, letter) in letters.char_indices() {
            let rest = &letters[at + letter.len_utf8()..];
            // `-db`, `-sb`, `-ws` and `-li` are flags, not letters with a
            // value or a list.
            let flag = matches!(
                (before, letter),
                (Some('d' | 's'), 'b') | (Some('w'), 's') | (Some('l'), 'i')
            );
            before = Some(letter);
            if flag {
                continue;
            }
            // A value stands in the next argument when nothing follows the
            // option's name, and is the rest of this one when something does;
            // either way it ends the bundle.
            let mut separate = false;
            let mut inside = false;
            match letter {
                'm' => moves = true,
                '@' => from_input = true,
                // Bare, they open a list; with something after the letter
                // (`-xpat`, `-x=pat`) that is the one value, and it ends the
                // bundle.
                'x' | 'i' => {
                    list = rest.is_empty().then_some(if letter == 'x' {
                        ZipList::Exclude
                    } else {
                        ZipList::Include
                    });
                    inside = !rest.is_empty();
                }
                'b' | 'O' | 'P' | 'Z' => separate = rest.is_empty(),
                // `-t date` and `-tt date`, `-TT command`.
                't' => separate = rest.is_empty() || rest == "t",
                'T' => {
                    separate = rest == "T";
                    inside = rest.starts_with('T') && !separate;
                }
                // `-s size` and `-s100m` (`-sf` and its kin are flags).
                's' => {
                    separate = rest.is_empty();
                    inside = rest.starts_with(|c: char| c.is_ascii_digit());
                }
                // `-n suffixes` and `-n.mp3` (`-nw` is a flag).
                'n' => {
                    separate = rest.is_empty();
                    inside = !rest.is_empty() && !rest.starts_with('w');
                }
                // `-UN warn`, `-UN=warn` and `-UNwarn`: the Unicode option,
                // whose value is a word that ends in a letter that is an
                // option of its own.
                'U' => {
                    if let Some(after) = rest.strip_prefix('N') {
                        separate = after.is_empty();
                        inside = !after.is_empty();
                    }
                }
                // `-ds size` and `-ds10m`, `-lf file` and `-lfout`.
                'd' | 'l' => {
                    let name = if letter == 'd' { 's' } else { 'f' };
                    if let Some(after) = rest.strip_prefix(name) {
                        separate = after.is_empty();
                        inside = !after.is_empty();
                    }
                }
                _ => {}
            }
            if separate {
                iter.next();
            }
            if separate || inside || matches!(letter, 'b' | 'O' | 'P' | 'Z' | 't') {
                break;
            }
        }
    }
    if !moves {
        return Vec::new();
    }
    // The first operand is the archive, unless it is not known which it is.
    let skip = usize::from(
        positional
            .first()
            .is_some_and(|first| first.known().is_some()),
    );
    let mut members: Vec<Arg> = positional.split_off(skip.min(positional.len()));
    if members.is_empty() {
        members = included;
    }
    if from_input {
        members.push(Arg::Unknown("<names read from input>".to_string()));
    }
    members
}

/// What can be read of the start of an argument, as far as it is text: the
/// value of one that is known, and the text as written of one only known
/// when it runs (`-p"$PASS"` starts with `-p`).
fn readable(arg: &Arg) -> &str {
    match arg {
        Arg::Known(text) | Arg::Unknown(text) | Arg::Template { text, .. } => text,
        Arg::Input => "",
    }
}

/// Whether an argument can be nothing but a switch, however it expands: it
/// is only known when it runs and no letter of its start is plain text that
/// rules a switch out.
fn may_be_switch(arg: &Arg) -> bool {
    arg.known().is_none()
        && !readable(arg)
            .starts_with(|c: char| c.is_alphanumeric() || matches!(c, '.' | '/' | '~' | '\\' | '_'))
}

/// The files `7z a` and `7z u` delete after adding them, which `-sdel`
/// asks for: the operands after the archive's name, the patterns of `-i`,
/// and the lists named with `@`; with none of them, `*`. An argument whose
/// readable start is `-` is a switch whatever follows (`-p"$PASS"`); one
/// that may be `-i` adds a member only known when it runs. An argument
/// wholly unknown (`$OPTS`) may be a switch too, so the default `*` stays
/// among the members when the operands that are known leave none.
fn seven_zip_removes(args: &[Arg]) -> Vec<Arg> {
    let list = || Arg::Unknown("<files from a list>".to_string());
    let mut deletes = false;
    let mut adds = false;
    let mut included = false;
    let mut positional = 0;
    // The operands that cannot be a switch: the command, the archive and
    // the names after it.
    let mut definite = 0;
    let mut members = Vec::new();
    let mut options_done = false;
    for arg in args {
        let start = readable(arg);
        let is_switch = !options_done && start.starts_with('-') && start.len() > 1;
        let text = match arg.known() {
            Some(text) if is_switch => text,
            None if is_switch => {
                // Only known when it runs: a switch, which may be `-i`.
                let letter = start[1..].chars().next();
                if letter.is_none_or(|c| c.eq_ignore_ascii_case(&'i') || !c.is_ascii_alphabetic()) {
                    included = true;
                    members.push(Arg::Unknown(arg.text().to_string()));
                }
                continue;
            }
            _ => {
                positional += 1;
                definite += usize::from(!may_be_switch(arg));
                match positional {
                    // The command: one that is not known may add.
                    1 => {
                        adds = arg.known().is_none_or(|text| {
                            matches!(text.to_ascii_lowercase().as_str(), "a" | "u")
                        });
                    }
                    2 => {}
                    _ => members.push(match arg.known() {
                        Some(text) if text.starts_with('@') => list(),
                        _ => arg.clone(),
                    }),
                }
                continue;
            }
        };
        if text == "--" {
            options_done = true;
        } else if text.eq_ignore_ascii_case("-sdel") {
            deletes = true;
        } else if text
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("-i"))
        {
            // `-i!pattern`, `-ir!pattern`, `-ir0!pattern`, `-i@list`.
            included = true;
            let rest = text[2..]
                .trim_start_matches(|c: char| matches!(c, 'r' | 'R' | '-') || c.is_ascii_digit());
            if let Some(pattern) = rest.strip_prefix('!') {
                members.push(Arg::Known(pattern.to_string()));
            } else if rest.starts_with('@') {
                members.push(list());
            }
        }
    }
    // Given no names and no `-i`, `a` and `u` pack everything under the
    // working directory (the default wildcard `*`). An argument that may be
    // a switch leaves it as one reading, so it stays when the operands that
    // are certain are no more than the command and the archive.
    let all_known = members.iter().all(|member| member.known().is_some());
    if !included && positional >= 2 && definite <= 2 && all_known {
        members.push(Arg::Known("*".to_string()));
    }
    if deletes && adds {
        members
    } else {
        Vec::new()
    }
}
